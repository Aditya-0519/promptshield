#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pkg = require('../package.json');
const { loadAttacks, runScan } = require('./scanner');
const { makeJudge, llmAvailable } = require('./judge');
const { renderHtml, summarize } = require('./report');
const { loadConfig, resolveConfig, validateConfig } = require('./config');
const { computeExit } = require('./exitcode');
const { makeRedactor, redactDeep } = require('./redact');
const { toSarif } = require('./formats/sarif');
const { toJunit } = require('./formats/junit');
const { runInit, PRESETS } = require('./init');
const { isLocalUrl } = require('./transports/util');
const { transportName, defaultUrl } = require('./transports');
const { formatRate } = require('./stats');

const noColor = !!process.env.NO_COLOR || !process.stdout.isTTY;
const paint = (code) => (s) => (noColor ? String(s) : `\x1b[${code}m${s}\x1b[0m`);
const C = { red: paint(31), green: paint(32), yellow: paint(33), dim: paint(2), bold: paint(1) };

const BOOLEAN = new Set([
  'strict', 'help', 'version', 'llm-judge', 'no-redact', 'redact', 'i-own-this-target', 'force', 'quiet', 'list',
]);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (eq > 0) args[key] = a.slice(eq + 1);
      else if (BOOLEAN.has(key)) args[key] = true;
      else if (argv[i + 1] === undefined || argv[i + 1].startsWith('--')) args[key] = true;
      else { args[key] = argv[i + 1]; i += 1; }
    } else args._.push(a);
  }
  return args;
}

function usage() {
  console.log(`
${C.bold('PromptShield')} ${pkg.version} - leak and injection testing for LLM apps, in your terminal and CI

Usage:
  promptshield init [--provider openai|anthropic|gemini|ollama|http]   create a starter config + canaries
  promptshield scan [options]                                           run the attacks

Target (config file or flags):
  --config <file>        Target config (default: promptshield.config.json)
  --provider <name>      openai | anthropic | gemini | ollama | http   (openai also covers vLLM, LM Studio, Groq, Together, OpenRouter, Ollama /v1)
  --url <url>            Endpoint URL
  --model <name>         Model name (provider transports)

Run:
  --trials <n>           Run every attack n times and report attack success rate (default 1; use 5+ for real models)
  --concurrency <n>      Parallel requests (default 1)
  --threshold <0-1>      Highest tolerated attack success rate (default 0: any successful attack fails the run)
  --category <list>      Comma-separated attack categories
  --attacks <dirs>       Comma-separated attack directories (default: bundled attacks)
  --strict               Exit 3 if any attack was inconclusive
  --llm-judge            Second opinion from an LLM (GEMINI_API_KEY, or JUDGE_API_KEY + JUDGE_BASE_URL)
  --i-own-this-target    Required for non-local URLs: confirms you may test this target

Output:
  --out <dir>            Report folder (default: reports)
  --format <list>        html,json,sarif,junit (default: html,json)
  --no-redact            Keep full secrets in reports (default: redacted)

Exit codes: 0 ok · 1 vulnerable · 2 usage/config error · 3 inconclusive with --strict
Only scan apps you own or have written permission to test.
`);
}

function fail(msg) {
  console.error(C.red(msg));
  process.exit(2);
}

function buildConfig(args) {
  const configPath = path.resolve(args.config || 'promptshield.config.json');
  let config;
  if (fs.existsSync(configPath)) {
    config = loadConfig(configPath);
  } else if (args.provider || args.url) {
    config = resolveConfig({});
  } else {
    fail(`Config not found: ${configPath}\nRun "promptshield init" to create one.`);
  }
  if (args.provider) config.transport = String(args.provider);
  if (typeof args.url === 'string') config.url = args.url;
  if (typeof args.model === 'string') config.model = args.model;
  if (args.provider && config.systemPromptFile === undefined && !config.systemPrompt) { /* nothing */ }
  config.secrets = config.secrets || [];
  return { config, configPath };
}

function reportMeta(config, configPath, opts) {
  const safeConfig = JSON.stringify({ ...config, apiKey: undefined, headers: undefined, systemPrompt: undefined });
  return {
    target: config.url || defaultUrl(config),
    model: config.model || undefined,
    transport: transportName(config),
    attackDirectory: opts.attackDirs.join(', '),
    date: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
    judge: opts.useLlm ? 'rules + LLM' : 'rules',
    trials: opts.trials,
    concurrency: opts.concurrency,
    threshold: opts.threshold,
    redacted: opts.redact,
    toolVersion: pkg.version,
    configHash: crypto.createHash('sha256').update(safeConfig).digest('hex').slice(0, 16),
    configFile: path.basename(configPath),
  };
}

function printResult(r) {
  const tag =
    r.verdict === 'vulnerable' ? C.red('VULNERABLE')
      : r.verdict === 'safe' ? C.green('safe      ')
        : r.verdict === 'inconclusive' ? C.yellow('INCONCLUSIVE')
          : C.yellow('error     ');
  const t = r.trials;
  const rate = t && t.total > 1 && t.conclusive ? ` ${C.bold(`[leaked ${formatRate(t.successes, t.conclusive)}]`)}` : '';
  console.log(`${tag} ${r.attack.id} ${r.attack.name} ${C.dim(`[${r.attack.severity}]`)}${rate}`);
  if (r.verdict !== 'safe') console.log(C.dim(`           ${r.reason}`));
  const ev = r.evidence;
  if (ev && ev.firstLeakStep) {
    console.log(C.dim(`           First assistant leak: step ${ev.firstLeakStep}; assessment: ${ev.extractionAssessment}`));
  }
  if (ev && ev.stageEvidence && ev.stageEvidence.length) {
    const passed = ev.stageEvidence.filter((st) => st.passed).length;
    console.log(C.dim(`           Stage sequence: ${ev.stageSequenceComplete ? 'complete' : 'incomplete'} (${passed}/${ev.stageEvidence.length} stage markers observed)`));
  }
}

async function scan(args) {
  const { config, configPath } = buildConfig(args);

  const categories = typeof args.category === 'string' ? args.category.split(',') : null;
  const defaultDir = path.join(__dirname, '..', 'attacks');
  const attackDirs = (typeof args.attacks === 'string' ? args.attacks.split(',') : [defaultDir]).map((d) => path.resolve(d));
  let attacks = [];
  for (const dir of attackDirs) {
    if (!fs.existsSync(dir)) fail(`Attack directory not found: ${dir}`);
    attacks = attacks.concat(loadAttacks(dir, categories));
  }
  if (!attacks.length) fail('No attacks selected.');
  const ids = new Set();
  for (const a of attacks) {
    if (ids.has(a.id)) fail(`Duplicate attack id "${a.id}" across attack directories.`);
    ids.add(a.id);
  }

  const trials = Number(args.trials || config.trials || 1);
  const concurrency = Number(args.concurrency || config.concurrency || 1);
  const threshold = args.threshold !== undefined ? Number(args.threshold) : Number(config.threshold || 0);
  config.trials = trials;
  config.concurrency = concurrency;
  config.threshold = threshold;
  const redact = !args['no-redact'];
  const strict = !!args.strict;

  const { errors, warnings } = validateConfig(config, attacks);
  warnings.forEach((w) => console.error(C.yellow(`warning: ${w}`)));
  if (errors.length) fail(`Invalid config:\n  - ${errors.join('\n  - ')}`);

  const target = config.url || defaultUrl(config);
  const targets = [...new Set([target, config.startUrl].filter(Boolean))];
  const unauthorizedTarget = targets.find((target) =>
    !isLocalUrl(target) && !args['i-own-this-target'] && config.authorized !== true
  );
  if (unauthorizedTarget) {
    fail(
      `Refusing to scan ${unauthorizedTarget}: it is not a local address.\n` +
      'PromptShield sends attack prompts. Only scan systems you own or are authorised to test, then re-run with\n' +
      '--i-own-this-target (or set "authorized": true in the config for CI).'
    );
  }

  const useLlm = !!args['llm-judge'] && llmAvailable();
  if (args['llm-judge'] && !useLlm) console.error(C.yellow('No LLM judge credentials found (GEMINI_API_KEY or JUDGE_API_KEY); using rules only.'));

  if (!args.quiet) {
    console.log(C.bold(`\nScanning ${target} with ${attacks.length} attacks x ${trials} trial(s)...\n`));
  }

  const results = await runScan(config, attacks, {
    judge: makeJudge({ useLlm }),
    trials,
    concurrency,
    onResult: args.quiet ? undefined : printResult,
  });

  const outDir = path.resolve(args.out || 'reports');
  fs.mkdirSync(outDir, { recursive: true });
  const formats = new Set(String(args.format === true ? 'html,json' : args.format || 'html,json').split(',').map((f) => f.trim()));
  const meta = reportMeta(config, configPath, { attackDirs, useLlm, trials, concurrency, threshold, redact });
  const redactor = redact ? makeRedactor(config) : (s) => s;
  const view = redact ? redactDeep(results, redactor) : results;
  const s = summarize(results);
  const written = [];

  if (formats.has('html')) {
    fs.writeFileSync(path.join(outDir, 'report.html'), renderHtml(view, meta));
    written.push('report.html');
  }
  if (formats.has('json')) {
    const jsonResults = view.map((r) => ({
      id: r.attack.id, name: r.attack.name, category: r.attack.category, severity: r.attack.severity,
      verdict: r.verdict, cause: r.cause, reason: r.reason,
      attackSuccessRate: r.trials ? r.trials.asr : undefined,
      trials: r.trials,
      provenance: r.response.provenance ? r.response.provenance.source : undefined,
      provenanceVerified: r.provenanceVerified,
      prompt: r.attack.prompt, attackSteps: r.attack.steps,
      response: r.response.text, responseSteps: r.response.steps,
      evidence: r.evidence, durationMs: r.response.ms,
    }));
    fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify({ meta, summary: s, results: jsonResults }, null, 2));
    written.push('report.json');
  }
  if (formats.has('sarif')) {
    const uri = path.relative(process.cwd(), configPath).split(path.sep).join('/') || 'promptshield.config.json';
    fs.writeFileSync(path.join(outDir, 'report.sarif'), JSON.stringify(toSarif(view, { version: pkg.version, artifactUri: uri }), null, 2));
    written.push('report.sarif');
  }
  if (formats.has('junit')) {
    fs.writeFileSync(path.join(outDir, 'report.junit.xml'), toJunit(view, { strict, threshold }));
    written.push('report.junit.xml');
  }

  console.log(
    `\n${C.bold('Result:')} ${s.vulnerable} vulnerable, ${s.safe} safe, ${s.inconclusive} inconclusive, ${s.errors} errors  ` +
    `(${s.score === null ? 'n/a' : s.score + '%'} of conclusive attacks resisted)`
  );
  if (trials > 1 && s.overallAsr !== null) {
    console.log(`Overall attack success rate: ${Math.round(s.overallAsr * 100)}% across ${s.trialsRun} trials.`);
  }
  console.log(C.dim('"safe" means no leak was observed in the trials run. It does not mean the app is secure.'));
  if (s.inconclusive > 0) console.log(C.yellow(`${s.inconclusive} attack(s) were inconclusive and are NOT confirmed safe.`));
  if (!redact) console.log(C.yellow('Reports are UNREDACTED and contain full secrets. Do not share them.'));
  console.log(`Reports: ${written.map((w) => path.join(outDir, w)).join(', ')}\n`);

  process.exit(computeExit(results, { threshold, strict }).code);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];

  if (args.version) { console.log(pkg.version); return; }
  if (args.help || !cmd) { usage(); process.exit(args.help ? 0 : 2); }
  if (cmd === 'init') process.exit(await runInit(args));
  if (cmd === 'scan') return scan(args);
  usage();
  process.exit(2);
}

main().catch((err) => {
  console.error(C.red(err.message || err));
  if (process.env.PROMPTSHIELD_DEBUG) console.error(err.stack);
  process.exit(2);
});
