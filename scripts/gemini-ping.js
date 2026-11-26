// Talks to Gemini directly (no ABTalks) with a tiny prompt, so you can see whether
// your API key and model respond, and which models your key can use.
// Usage (from the promptshield folder):  node scripts/gemini-ping.js
// Optional: node scripts/gemini-ping.js "C:\path\to\abtalks-ai-interviewer\server\.env"
// Your API key is read from that .env file and is never printed.
const fs = require('fs');
const path = require('path');

const envPath = path.resolve(process.argv[2] || '../abtalks-ai-interviewer/server/.env');
const ROOT =
  (process.env.GOOGLE_GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com').replace(/\/$/, '') + '/v1beta';
const TIMEOUT_MS = Number(process.env.PING_TIMEOUT_MS) || 25000;

function readEnv(file) {
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || line.trim().startsWith('#')) continue;
    out[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
  return out;
}

async function call(key, url, init) {
  const started = Date.now();
  try {
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch (_) { /* not JSON */ }
    return { ok: res.ok, status: res.status, ms: Date.now() - started, json };
  } catch (err) {
    const timedOut = err.name === 'TimeoutError';
    return {
      ok: false,
      status: 0,
      ms: Date.now() - started,
      error: timedOut ? `no answer after ${TIMEOUT_MS / 1000} s` : (err.cause && err.cause.code) || err.message,
      timedOut,
    };
  }
}

async function ping(key, model) {
  const r = await call(key, `${ROOT}/models/${model}:generateContent`, {
    method: 'POST',
    body: JSON.stringify({ contents: [{ parts: [{ text: 'Reply with the single word OK.' }] }] }),
  });
  let line;
  if (r.ok) line = `OK    HTTP ${r.status}, ${r.ms} ms`;
  else if (r.error) line = `FAIL  ${r.error}`;
  else line = `FAIL  HTTP ${r.status}: ${String((r.json && r.json.error && r.json.error.message) || '').slice(0, 140)}`;
  console.log(`  ${model.padEnd(34)} ${line}`);
  return r;
}

(async () => {
  if (!fs.existsSync(envPath)) {
    console.log(`\nCannot find ${envPath}\nPass the path to server/.env as an argument.\n`);
    process.exit(1);
  }
  const env = readEnv(envPath);
  const key = env.GEMINI_API_KEY;
  const model = env.GEMINI_MODEL || '(not set)';
  if (!key) {
    console.log('\nGEMINI_API_KEY is missing in that .env file.\n');
    process.exit(1);
  }

  console.log(`\nReading ${envPath}`);
  console.log(`Configured model: ${model}`);
  console.log(`Each call waits up to ${TIMEOUT_MS / 1000} s\n`);

  console.log('1) Models your key can use for generateContent:');
  const list = await call(key, `${ROOT}/models?pageSize=200`, { method: 'GET' });
  let names = [];
  if (list.ok && list.json && Array.isArray(list.json.models)) {
    names = list.json.models
      .filter((m) => (m.supportedGenerationMethods || []).includes('generateContent'))
      .map((m) => String(m.name).replace(/^models\//, ''));
    console.log(`  ${names.length} models. Configured model is ${names.includes(model) ? 'IN' : 'NOT in'} this list.`);
    console.log('  ' + names.slice(0, 25).join(', ') + (names.length > 25 ? ', ...' : ''));
  } else {
    const why = list.error || `HTTP ${list.status}: ${String((list.json && list.json.error && list.json.error.message) || '').slice(0, 140)}`;
    console.log(`  could not list models (${why})`);
  }

  console.log('\n2) Tiny test prompt, configured model, then alternatives:');
  const main = await ping(key, model);
  const alts = names
    .filter((n) => /flash/.test(n) && !/image|tts|live|audio|embedding/.test(n) && n !== model)
    .slice(0, 3);
  const altResults = [];
  for (const n of alts) altResults.push({ name: n, r: await ping(key, n) });

  const working = altResults.filter((a) => a.r.ok).sort((a, b) => a.r.ms - b.r.ms)[0];
  console.log('');
  if (main.ok && main.ms < 10000) {
    console.log('RESULT: your key and model answer a small prompt quickly.');
    console.log('If ABTalks still hangs, the full interview prompt is hitting a busy model. Try an alternative model or wait.');
  } else if (working) {
    console.log(`RESULT: "${model}" is failing or slow, but "${working.name}" works (${working.r.ms} ms).`);
    console.log(`Fix: in abtalks-ai-interviewer/server/.env set  GEMINI_MODEL=${working.name}`);
    console.log('Then type  rs  in the backend terminal and run  npm run check.');
  } else if (!main.ok && main.status && [400, 401, 403].includes(main.status)) {
    console.log('RESULT: Google rejected the key or request. Check GEMINI_API_KEY in .env (no quotes or spaces) and that the key is enabled for the Gemini API.');
  } else {
    console.log('RESULT: no model answered in time. Google (or your project) is overloaded right now. Wait a few minutes and run this again.');
  }
  console.log('');
})();