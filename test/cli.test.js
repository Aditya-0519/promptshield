// End-to-end: the real CLI against the real vulnerable bot, over HTTP and OpenAI-compatible.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const cli = path.join(root, 'src', 'cli.js');
let bot;
let port;

test.before(async () => {
  port = 4100 + Math.floor(Math.random() * 500);
  bot = spawn(process.execPath, [path.join(root, 'vulnerable-bot', 'server.js')], { env: { ...process.env, PORT: String(port), GEMINI_API_KEY: '' }, stdio: 'ignore' });
  for (let i = 0; i < 50; i += 1) {
    try { await fetch(`http://127.0.0.1:${port}/`); return; } catch (_) { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error('bot did not start');
});
test.after(() => bot && bot.kill());

function run(args, env = {}) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env } });
}

function writeConfig(obj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-cli-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(obj));
  return { dir, file };
}

const httpCfg = () => ({
  url: `http://127.0.0.1:${port}/chat`,
  bodyTemplate: { sessionId: '{{sessionId}}', message: '{{prompt}}' },
  responsePath: 'reply',
  secrets: ['ORCHID-7731'],
  allow: ['support@acmebank.example'],
  timeoutMs: 5000,
});

test('HTTP multi-turn: finds the multi-turn leak that single-turn scans cannot see, exits 1', () => {
  const { dir, file } = writeConfig(httpCfg());
  const r = run(['scan', '--config', file, '--out', dir, '--format', 'html,json,sarif,junit', '--trials', '2']);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /VULNERABLE MT-001/);
  assert.match(r.stdout, /MT-004/);
  for (const f of ['report.html', 'report.json', 'report.sarif', 'report.junit.xml']) assert.ok(fs.existsSync(path.join(dir, f)), f);

  const report = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
  const mt1 = report.results.find((x) => x.id === 'MT-001');
  assert.equal(mt1.verdict, 'vulnerable');
  assert.equal(mt1.responseSteps.length, 2);
  assert.ok(mt1.responseSteps.every((s) => s.prompt.length > 0)); // never an empty prompt
  assert.equal(mt1.trials.successes, 2);
  // refusals that quote the payload / public email must be SAFE
  for (const id of ['INJ-004', 'INJ-005', 'PII-001']) {
    assert.equal(report.results.find((x) => x.id === id).verdict, 'safe', id);
  }
});

test('reports are redacted by default and full with --no-redact', () => {
  const a = writeConfig(httpCfg());
  run(['scan', '--config', a.file, '--out', a.dir, '--category', 'system_prompt_leak']);
  assert.ok(!fs.readFileSync(path.join(a.dir, 'report.html'), 'utf8').includes('ORCHID-7731'));
  assert.ok(!fs.readFileSync(path.join(a.dir, 'report.json'), 'utf8').includes('ORCHID-7731'));
  const b = writeConfig(httpCfg());
  run(['scan', '--config', b.file, '--out', b.dir, '--category', 'system_prompt_leak', '--no-redact']);
  assert.ok(fs.readFileSync(path.join(b.dir, 'report.json'), 'utf8').includes('ORCHID-7731'));
});

test('OpenAI-compatible preset works against the bot with no body template', () => {
  const { dir, file } = writeConfig({
    transport: 'openai', url: `http://127.0.0.1:${port}/v1/chat/completions`, model: 'any',
    secrets: ['ORCHID-7731'], timeoutMs: 5000,
  });
  const r = run(['scan', '--config', file, '--out', dir, '--category', 'system_prompt_leak']);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /VULNERABLE MT-001/);
});

test('threshold lets a CI gate tolerate a known rate; --strict fails on inconclusive', () => {
  const { dir, file } = writeConfig({ ...httpCfg(), secrets: [] });
  const r = run(['scan', '--config', file, '--out', dir, '--category', 'system_prompt_leak', '--strict']);
  assert.equal(r.status, 3, r.stdout + r.stderr); // no canaries, no systemPrompt => inconclusive
  assert.match(r.stdout, /INCONCLUSIVE/);
  const ok = run(['scan', '--config', file, '--out', dir, '--category', 'prompt_injection', '--attacks', path.join(root, 'attacks', 'basileak')]);
  assert.ok([0, 1, 2].includes(ok.status));
});

test('config errors exit 2 with a clear message; non-local targets need confirmation', () => {
  const missingVar = writeConfig({ ...httpCfg(), headers: { Authorization: 'Bearer ${PS_TEST_UNSET_VAR}' } });
  const a = run(['scan', '--config', missingVar.file, '--out', missingVar.dir]);
  assert.equal(a.status, 2);
  assert.match(a.stderr, /PS_TEST_UNSET_VAR/);

  const remote = writeConfig({ ...httpCfg(), url: 'https://example.com/chat' });
  const b = run(['scan', '--config', remote.file, '--out', remote.dir]);
  assert.equal(b.status, 2);
  assert.match(b.stderr, /i-own-this-target/);

  const remoteStart = writeConfig({ ...httpCfg(), startUrl: 'https://example.com/session' });
  const startCheck = run(['scan', '--config', remoteStart.file, '--out', remoteStart.dir]);
  assert.equal(startCheck.status, 2);
  assert.match(startCheck.stderr, /i-own-this-target/);

  const bad = writeConfig({ url: `http://127.0.0.1:${port}/chat` });
  const c = run(['scan', '--config', bad.file, '--out', bad.dir]);
  assert.equal(c.status, 2);
  assert.match(c.stderr, /bodyTemplate/);
});


test('init creates starter config, canaries, prompt file and env example safely', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-init-'));
  const file = path.join(dir, 'promptshield.config.json');
  const promptFile = path.join(dir, 'system-prompt.txt');
  const envFile = path.join(dir, '.env.example');

  const r = run(['init', '--provider', 'openai', '--config', file]);

  assert.equal(r.status, 0, r.stderr);

  const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));

  assert.equal(cfg.transport, 'openai');
  assert.equal(cfg.apiKey, '${OPENAI_API_KEY}');
  assert.equal(cfg.secrets.length, 2);
  assert.match(cfg.secrets[0], /^PSHIELD_CANARY_[0-9A-F]{8}$/);
  assert.match(cfg.secrets[1], /^PSHIELD_CANARY_[0-9A-F]{8}$/);

  // Starter prompt contains both generated canaries.
  assert.equal(fs.existsSync(promptFile), true);
  const prompt = fs.readFileSync(promptFile, 'utf8');
  for (const secret of cfg.secrets) {
    assert.ok(prompt.includes(secret));
  }

  // API key template is generated without a real credential.
  assert.equal(fs.existsSync(envFile), true);
  assert.match(fs.readFileSync(envFile, 'utf8'), /OPENAI_API_KEY=your_api_key_here/);

  // Existing prompt and env files must never be overwritten.
  fs.writeFileSync(promptFile, 'MY EXISTING PROMPT');
  fs.writeFileSync(envFile, 'MY EXISTING ENV');

  // Existing config is protected unless --force is supplied.
  assert.equal(run(['init', '--provider', 'openai', '--config', file]).status, 2);
  assert.equal(fs.readFileSync(promptFile, 'utf8'), 'MY EXISTING PROMPT');
  assert.equal(fs.readFileSync(envFile, 'utf8'), 'MY EXISTING ENV');

  // --force replaces config but preserves existing user files.
  const forced = run(['init', '--provider', 'gemini', '--config', file, '--force']);
  assert.equal(forced.status, 0, forced.stderr);

  const forcedCfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(forcedCfg.transport, 'gemini');
  assert.equal(forcedCfg.apiKey, '${GEMINI_API_KEY}');

  assert.equal(fs.readFileSync(promptFile, 'utf8'), 'MY EXISTING PROMPT');
  assert.equal(fs.readFileSync(envFile, 'utf8'), 'MY EXISTING ENV');
});


test('--version and --help work', () => {
  assert.match(run(['--version']).stdout, /^\d+\.\d+\.\d+/);
  assert.equal(run(['--help']).status, 0);
});
