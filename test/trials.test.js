const test = require('node:test');
const assert = require('node:assert/strict');
const { wilson, formatRate } = require('../src/stats');
const { runScan } = require('../src/scanner');
const { makeJudge } = require('../src/judge');
const { computeExit } = require('../src/exitcode');
const { summarize } = require('../src/report');
const http = require('node:http');

test('wilson interval matches known values', () => {
  const ci = wilson(3, 5);
  assert.ok(Math.abs(ci.low - 0.231) < 0.01, `low ${ci.low}`);
  assert.ok(Math.abs(ci.high - 0.882) < 0.01, `high ${ci.high}`);
  assert.equal(wilson(0, 0), null);
  assert.equal(wilson(0, 10).low, 0);
  assert.ok(wilson(10, 10).high === 1);
  assert.equal(formatRate(3, 5), '3/5 (60%, 95% CI 23-88%)');
});

async function flaky(pattern) {
  let n = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const leak = pattern[n % pattern.length]; n += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reply: leak ? 'code CANARY-1' : 'no' }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}/c`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

const attack = { id: 'A', name: 'a', category: 'system_prompt_leak', severity: 'high', prompt: 'p', detect: {}, fix: 'f' };
const cfg = (url, extra = {}) => ({ url, bodyTemplate: { m: '{{prompt}}' }, responsePath: 'reply', secrets: ['CANARY-1'], timeoutMs: 2000, ...extra });

test('3 leaks in 5 trials => ASR 60% with the right interval', async (t) => {
  const s = await flaky([true, false, true, false, true]);
  t.after(s.close);
  const [r] = await runScan(cfg(s.url), [attack], { judge: makeJudge({}), trials: 5 });
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.trials.total, 5);
  assert.equal(r.trials.successes, 3);
  assert.equal(r.trials.conclusive, 5);
  assert.equal(r.trials.asr, 0.6);
  assert.ok(Math.abs(r.trials.ci95[0] - 0.231) < 0.01);
  assert.match(r.reason, /3\/5/);
});

test('no leak in any trial => SAFE, worded as "not observed", never "secure"', async (t) => {
  const s = await flaky([false]);
  t.after(s.close);
  const [r] = await runScan(cfg(s.url), [attack], { judge: makeJudge({}), trials: 4, concurrency: 2 });
  assert.equal(r.verdict, 'safe');
  assert.equal(r.trials.asr, 0);
  assert.match(r.reason, /not proof of safety/);
});

test('trial failures are inconclusive trials, not safe ones', async () => {
  const [r] = await runScan(cfg('http://127.0.0.1:9/c', { retries: 0 }), [attack], { judge: makeJudge({}), trials: 3 });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.trials.inconclusive, 3);
  assert.equal(r.trials.asr, null);
});

test('concurrency preserves attack order in results', async (t) => {
  const s = await flaky([false]);
  t.after(s.close);
  const attacks = ['A', 'B', 'C', 'D'].map((id) => ({ ...attack, id }));
  const results = await runScan(cfg(s.url), attacks, { judge: makeJudge({}), trials: 2, concurrency: 4 });
  assert.deepEqual(results.map((r) => r.attack.id), ['A', 'B', 'C', 'D']);
});

test('exit code: threshold on attack success rate, strict on inconclusive', () => {
  const v = (asr) => ({ verdict: 'vulnerable', trials: { asr } });
  assert.equal(computeExit([v(0.2)], { threshold: 0 }).code, 1);
  assert.equal(computeExit([v(0.2)], { threshold: 0.25 }).code, 0);
  assert.equal(computeExit([v(0.5)], { threshold: 0.25 }).code, 1);
  assert.equal(computeExit([{ verdict: 'inconclusive' }], {}).code, 0);
  assert.equal(computeExit([{ verdict: 'inconclusive' }], { strict: true }).code, 3);
  assert.equal(computeExit([{ verdict: 'safe' }], { strict: true }).code, 0);
});

test('summary reports overall attack success rate', () => {
  const s = summarize([
    { verdict: 'vulnerable', attack: { severity: 'high' }, trials: { total: 5, successes: 3, conclusive: 5 } },
    { verdict: 'safe', attack: { severity: 'low' }, trials: { total: 5, successes: 0, conclusive: 5 } },
  ]);
  assert.equal(s.trialsRun, 10);
  assert.equal(s.overallAsr, 0.3);
});
