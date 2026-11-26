#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { loadAttacks, runScan } = require('./scanner');
const { makeJudge } = require('./judge');
const { renderHtml, summarize } = require('./report');

const C = {
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[key] = true;
      else { args[key] = next; i++; }
    } else args._.push(a);
  }
  return args;
}

function usage() {
  console.log(`
${C.bold('PromptShield')} - security scanner for LLM apps

Usage:
  promptshield scan [options]

Options:
  --strict             Exit 3 if any attack was inconclusive (recommended for CI)
  --config <file>      Target config (default: promptshield.config.json)
  --category <list>    Comma-separated: system_prompt_leak,prompt_injection,data_leak
  --out <dir>          Report folder (default: reports)
  --llm-judge          Use Gemini as a second judge (needs GEMINI_API_KEY)
  --help               Show this help

Exit code is 1 if any vulnerability is found (handy for CI).
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args._[0] !== 'scan') { usage(); process.exit(args.help ? 0 : 2); }

  const configPath = path.resolve(args.config || 'promptshield.config.json');
  if (!fs.existsSync(configPath)) {
    console.error(C.red(`Config not found: ${configPath}`));
    process.exit(2);
  }
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const categories = typeof args.category === 'string' ? args.category.split(',') : null;
  const attacks = loadAttacks(path.join(__dirname, '..', 'attacks'), categories);
  const useLlm = !!args['llm-judge'];
  if (useLlm && !process.env.GEMINI_API_KEY) {
    console.error(C.yellow('GEMINI_API_KEY not set, falling back to rule-based judging.'));
  }

  console.log(C.bold(`\nScanning ${config.url} with ${attacks.length} attacks...\n`));
  const results = await runScan(config, attacks, {
    judge: makeJudge({ useLlm: useLlm && !!process.env.GEMINI_API_KEY }),
    onResult: (r) => {
      const tag =
        r.verdict === 'vulnerable' ? C.red('VULNERABLE') : r.verdict === 'safe' ? C.green('safe      ') : r.verdict === 'inconclusive' ? C.yellow('INCONCLUSIVE') : C.yellow('error     ');
      console.log(`${tag} ${r.attack.id} ${r.attack.name} ${C.dim(`[${r.attack.severity}]`)}`);
      if (r.verdict !== 'safe') console.log(C.dim(`           ${r.reason}`));
    },
  });

  const s = summarize(results);
  const outDir = path.resolve(args.out || 'reports');
  fs.mkdirSync(outDir, { recursive: true });
  const meta = {
    target: config.url,
    date: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
    judge: useLlm && process.env.GEMINI_API_KEY ? 'rules + Gemini' : 'rules',
  };
  fs.writeFileSync(path.join(outDir, 'report.html'), renderHtml(results, meta));
  fs.writeFileSync(
    path.join(outDir, 'report.json'),
    JSON.stringify({ meta, summary: s, results: results.map((r) => ({
      id: r.attack.id, name: r.attack.name, category: r.attack.category, severity: r.attack.severity,
      verdict: r.verdict, cause: r.cause, reason: r.reason,
      provenance: r.response.provenance ? r.response.provenance.source : undefined,
      provenanceVerified: r.provenanceVerified,
      prompt: r.attack.prompt, response: r.response.text,
    })) }, null, 2)
  );

  console.log(
    `\n${C.bold('Result:')} ${s.vulnerable} vulnerable, ${s.safe} safe, ${s.inconclusive} inconclusive, ${s.errors} errors  ` +
      `(${s.score === null ? 'n/a' : s.score + '%'} of conclusive attacks resisted)`
  );
  if (s.inconclusive > 0) {
    console.log(C.yellow(`${s.inconclusive} attack(s) were inconclusive and are NOT confirmed safe.`));
  }
  console.log(`Report: ${path.join(outDir, 'report.html')}\n`);
    if (s.vulnerable > 0) process.exit(1);
  if (args.strict && s.inconclusive > 0) process.exit(3);
  process.exit(0);
}
main().catch((err) => { console.error(C.red(err.stack || err.message)); process.exit(2); });