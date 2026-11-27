const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { sendPrompt, runScan } = require('../src/scanner');
const { makeJudge } = require('../src/judge');
const { expandEnv, validateConfig } = require('../src/config');

function startServer(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let json;
      try { json = JSON.parse(body); } catch (_) { /* not json */ }
      requests.push({ url: req.url, headers: req.headers, body: json });
      handler({ req, res, json, n: requests.length, requests });
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({
        base: `http://127.0.0.1:${server.address().port}`,
        requests,
        close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
      })));
}

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

const threeStep = {
  id: 'T-3', category: 'system_prompt_leak', severity: 'high', name: 'three steps',
  steps: ['one', 'two: {{previousResponse}}', 'three'], detect: {}, fix: 'n/a',
};

test('HTTP transport: {{messages}} replays the whole conversation, no empty prompts', async (t) => {
  const s = await startServer(({ res, json: body, n }) => json(res, 200, { reply: `answer-${n}` }));
  t.after(s.close);
  const r = await sendPrompt({
    url: `${s.base}/chat`,
    bodyTemplate: { messages: '{{messages}}' },
    responsePath: 'reply',
    timeoutMs: 3000,
  }, threeStep);

  assert.equal(r.ok, true);
  assert.equal(s.requests.length, 3);
  assert.deepEqual(s.requests[0].body.messages, [{ role: 'user', content: 'one' }]);
  assert.equal(s.requests[1].body.messages.length, 3);
  assert.equal(s.requests[1].body.messages[2].content, 'two: answer-1'); // {{previousResponse}} filled
  assert.equal(s.requests[2].body.messages.length, 5);
  for (const q of s.requests) {
    for (const m of q.body.messages) assert.notEqual(m.content, '');
  }
  assert.equal(r.steps.length, 3);
});

test('HTTP transport: {{sessionId}} mode sends each step with the same session id', async (t) => {
  const s = await startServer(({ res, n }) => json(res, 200, { reply: `a${n}` }));
  t.after(s.close);
  await sendPrompt({
    url: `${s.base}/chat`,
    bodyTemplate: { sessionId: '{{sessionId}}', message: '{{prompt}}' },
    responsePath: 'reply',
    timeoutMs: 3000,
  }, threeStep);

  assert.equal(s.requests.length, 3);
  assert.deepEqual(s.requests.map((q) => q.body.message), ['one', 'two: a1', 'three']);
  assert.equal(new Set(s.requests.map((q) => q.body.sessionId)).size, 1);
});

test('HTTP transport: attack without prompt or steps sends nothing', async (t) => {
  const s = await startServer(({ res }) => json(res, 200, { reply: 'x' }));
  t.after(s.close);
  const r = await sendPrompt({ url: `${s.base}/c`, bodyTemplate: { m: '{{prompt}}' }, responsePath: 'reply' }, { id: 'X' });
  assert.equal(r.ok, false);
  assert.equal(r.cause, 'invalid_attack');
  assert.equal(s.requests.length, 0);
});

test('HTTP transport: missing responsePath target is an error, not a silent empty answer', async (t) => {
  const s = await startServer(({ res }) => json(res, 200, { other: 'x' }));
  t.after(s.close);
  const r = await sendPrompt({ url: `${s.base}/c`, bodyTemplate: { m: '{{prompt}}' }, responsePath: 'reply', timeoutMs: 2000 }, { id: 'X', prompt: 'hi' });
  assert.equal(r.ok, false);
  assert.equal(r.cause, 'invalid_response');
});

test('HTTP transport: SSE streaming reply is joined', async (t) => {
  const s = await startServer(({ res }) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write('data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n');
    res.write('data: {"choices":[{"delta":{"content":"lo"}}]}\n\n');
    res.end('data: [DONE]\n\n');
  });
  t.after(s.close);
  const r = await sendPrompt({ url: `${s.base}/c`, stream: true, bodyTemplate: { m: '{{prompt}}', stream: true }, timeoutMs: 2000 }, { id: 'X', prompt: 'hi' });
  assert.equal(r.ok, true);
  assert.equal(r.text, 'Hello');
});

test('OpenAI-compatible transport: replays history, sends system prompt and bearer key', async (t) => {
  const s = await startServer(({ res, n }) =>
    json(res, 200, { choices: [{ message: { role: 'assistant', content: `r${n}` } }] }));
  t.after(s.close);
  const r = await sendPrompt({
    transport: 'openai', url: `${s.base}/v1/chat/completions`, model: 'm1',
    apiKey: 'sk-test', systemPrompt: 'SYS', timeoutMs: 3000,
  }, threeStep);

  assert.equal(r.ok, true);
  assert.equal(s.requests.length, 3);
  assert.equal(s.requests[0].headers.authorization, 'Bearer sk-test');
  assert.equal(s.requests[0].body.model, 'm1');
  assert.deepEqual(s.requests[0].body.messages[0], { role: 'system', content: 'SYS' });
  assert.equal(s.requests[2].body.messages.length, 6); // system + 5 turns
});

test('OpenAI-compatible transport: content-part arrays are flattened', async (t) => {
  const s = await startServer(({ res }) =>
    json(res, 200, { choices: [{ message: { content: [{ type: 'text', text: 'A' }, { type: 'text', text: 'B' }] } }] }));
  t.after(s.close);
  const r = await sendPrompt({ transport: 'openai', url: `${s.base}/x`, model: 'm', timeoutMs: 2000 }, { id: 'X', prompt: 'hi' });
  assert.equal(r.text, 'AB');
});

test('Anthropic transport: system is top-level, x-api-key header, text blocks joined', async (t) => {
  const s = await startServer(({ res }) =>
    json(res, 200, { content: [{ type: 'thinking', thinking: 'hmm' }, { type: 'text', text: 'hello' }] }));
  t.after(s.close);
  const r = await sendPrompt({
    transport: 'anthropic', url: `${s.base}/v1/messages`, model: 'c', apiKey: 'k', systemPrompt: 'SYS', timeoutMs: 2000,
  }, { id: 'X', prompt: 'hi' });
  assert.equal(r.text, 'hello');
  assert.equal(s.requests[0].headers['x-api-key'], 'k');
  assert.ok(s.requests[0].headers['anthropic-version']);
  assert.equal(s.requests[0].body.system, 'SYS');
  assert.equal(s.requests[0].body.messages[0].role, 'user');
});

test('Gemini transport: contents use user/model roles and the key goes in a header', async (t) => {
  const s = await startServer(({ res, n }) =>
    json(res, 200, { candidates: [{ content: { parts: [{ text: `g${n}` }] } }] }));
  t.after(s.close);
  const r = await sendPrompt({
    transport: 'gemini', url: `${s.base}/v1beta/models/x:generateContent`, model: 'x', apiKey: 'gk', timeoutMs: 2000,
  }, { id: 'X', steps: ['a', 'b'] });
  assert.equal(r.ok, true);
  assert.equal(s.requests[1].headers['x-goog-api-key'], 'gk');
  assert.ok(!s.requests[1].url.includes('key='));
  assert.deepEqual(s.requests[1].body.contents.map((c) => c.role), ['user', 'model', 'user']);
});

test('HTTP transport: refuses redirects instead of following to another host', async (t) => {
  let redirectedRequests = 0;
  const destination = await startServer(({ res }) => {
    redirectedRequests += 1;
    json(res, 200, { reply: 'should not be reached' });
  });
  const source = await startServer(({ res }) => {
    res.writeHead(302, { Location: `${destination.base}/capture` });
    res.end();
  });
  t.after(async () => { await source.close(); await destination.close(); });

  const r = await sendPrompt({
    url: `${source.base}/redirect`,
    bodyTemplate: { message: '{{prompt}}' },
    responsePath: 'reply',
    retries: 0,
    timeoutMs: 2000,
  }, { id: 'REDIRECT-001', prompt: 'test' });

  assert.equal(r.ok, false);
  assert.equal(redirectedRequests, 0);
});

test('retry: 429 then success', async (t) => {
  const s = await startServer(({ res, n }) =>
    n === 1 ? json(res, 429, { error: 'slow down' }, { 'Retry-After': '0' }) : json(res, 200, { reply: 'ok' }));
  t.after(s.close);
  const r = await sendPrompt({
    url: `${s.base}/c`, bodyTemplate: { m: '{{prompt}}' }, responsePath: 'reply', timeoutMs: 2000, retryBaseMs: 5,
  }, { id: 'X', prompt: 'hi' });
  assert.equal(r.ok, true);
  assert.equal(s.requests.length, 2);
});

test('response size cap truncates huge bodies', async (t) => {
  const s = await startServer(({ res }) => { res.writeHead(200); res.end('x'.repeat(50000)); });
  t.after(s.close);
  const r = await sendPrompt({ url: `${s.base}/c`, bodyTemplate: { m: '{{prompt}}' }, maxResponseBytes: 1000, timeoutMs: 2000 }, { id: 'X', prompt: 'hi' });
  assert.ok(r.text.length <= 1100);
  assert.equal(r.steps[0].truncated, true);
});

test('multi-turn attack on a provider transport reaches the judge and finds a late leak', async (t) => {
  const s = await startServer(({ res, json: body }) => {
    const users = body.messages.filter((m) => m.role === 'user').length;
    json(res, 200, { choices: [{ message: { content: users >= 2 ? 'the code is CANARY-123' : 'hello' } }] });
  });
  t.after(s.close);
  const config = { transport: 'openai', url: `${s.base}/v1`, model: 'm', secrets: ['CANARY-123'], timeoutMs: 2000 };
  const [r] = await runScan(config, [{ id: 'M', category: 'x', severity: 'high', name: 'm', steps: ['hi', 'secret?'], detect: {} }], { judge: makeJudge({}) });
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.evidence.firstLeakStep, 2);
});

test('env expansion: ${VAR}, defaults, and missing variables', () => {
  const missing = new Set();
  const out = expandEnv({ a: 'Bearer ${K}', b: '${NOPE:-fallback}', c: ['${K}'], d: 5 }, missing, { K: 'secret' });
  assert.deepEqual(out, { a: 'Bearer secret', b: 'fallback', c: ['secret'], d: 5 });
  expandEnv('${MISSING_ONE}', missing, {});
  assert.deepEqual([...missing], ['MISSING_ONE']);
});

test('validateConfig: clear errors and the multi-turn warning', () => {
  const bad = validateConfig({ url: 'http://x' });
  assert.match(bad.errors.join(' '), /bodyTemplate/);
  const noModel = validateConfig({ transport: 'ollama', url: 'http://localhost:11434/api/chat' });
  assert.match(noModel.errors.join(' '), /model/);
  const warn = validateConfig(
    { url: 'http://x', bodyTemplate: { message: '{{prompt}}' }, responsePath: 'r', secrets: ['A'] },
    [{ id: 'm', steps: ['a', 'b'] }]
  );
  assert.equal(warn.errors.length, 0);
  assert.match(warn.warnings.join(' '), /Multi-turn/);
  assert.match(validateConfig({ url: 'http://x', bodyTemplate: { m: '{{prompt}}' }, tirals: 3 }).warnings.join(' '), /tirals/);
});
