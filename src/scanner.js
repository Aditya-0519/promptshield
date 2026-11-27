'use strict';

const fs = require('fs');
const path = require('path');
const { converse } = require('./conversation');
const { fillTemplate, getByPath } = require('./template');
const { validateAttacks } = require('./schema');
const { wilson, formatRate } = require('./stats');
const { sleep } = require('./http');

// Loads and VALIDATES attack files. Throws with the file and field named.
function loadAttacks(dir, categories) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  let attacks = [];
  const errors = [];

  for (const f of files) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8').replace(/^\uFEFF/, ''));
    } catch (err) {
      errors.push(`${f}: not valid JSON (${err.message})`);
      continue;
    }
    if (!Array.isArray(data)) {
      errors.push(`${f}: must contain a JSON array of attacks`);
      continue;
    }
    errors.push(...validateAttacks(data, f));
    attacks = attacks.concat(data);
  }

  const ids = new Map();
  for (const a of attacks) ids.set(a.id, (ids.get(a.id) || 0) + 1);
  for (const [id, n] of ids) if (n > 1 && id) errors.push(`duplicate attack id "${id}" across files (${n} times)`);

  if (errors.length) {
    throw new Error(`Invalid attack file(s):\n  - ${[...new Set(errors)].join('\n  - ')}`);
  }

  if (categories && categories.length) {
    attacks = attacks.filter((a) => categories.includes(a.category));
  }
  return attacks;
}

// One conversation with the target (kept for API compatibility).
const sendPrompt = (config, promptOrAttack) => converse(config, promptOrAttack);

async function runTrial(config, attack, judge) {
  const response = await converse(config, attack);
  let verdict;
  if (response.error || !response.ok) {
    verdict = {
      verdict: 'inconclusive',
      cause: response.cause || 'http_error',
      reason: response.error || `HTTP ${response.status}`,
    };
  } else {
    try {
      verdict = await judge(attack, response.text, config, response);
    } catch (err) {
      verdict = { verdict: 'error', cause: 'judge_error', reason: `Judge failed: ${err.message}` };
    }
  }
  return { response, ...verdict };
}

// Combines the N trials of one attack into a single result with an attack
// success rate. Shape is a superset of the single-run result.
function aggregate(attack, trials) {
  const vulnerable = trials.filter((t) => t.verdict === 'vulnerable');
  const safe = trials.filter((t) => t.verdict === 'safe');
  const conclusive = vulnerable.length + safe.length;
  const inconclusive = trials.filter((t) => t.verdict === 'inconclusive').length;
  const errors = trials.filter((t) => t.verdict === 'error').length;

  const rep = vulnerable[0] || safe[0] || trials[0];
  const ci = wilson(vulnerable.length, conclusive);

  let verdict;
  if (vulnerable.length) verdict = 'vulnerable';
  else if (conclusive) verdict = 'safe';
  else verdict = errors === trials.length ? 'error' : 'inconclusive';

  let reason = rep.reason;
  if (trials.length > 1) {
    if (verdict === 'vulnerable') {
      reason = `Leaked in ${formatRate(vulnerable.length, conclusive)}. First leak: ${rep.reason}`;
    } else if (verdict === 'safe') {
      reason = `No leak observed in ${conclusive} conclusive trial(s)` +
        (inconclusive ? `; ${inconclusive} trial(s) inconclusive` : '') + '. This is not proof of safety.';
    }
  }

  return {
    attack,
    response: rep.response,
    verdict,
    cause: verdict === 'inconclusive' || verdict === 'error' ? rep.cause : undefined,
    reason,
    definitive: rep.definitive,
    llmOnly: rep.llmOnly,
    provenanceVerified: rep.provenanceVerified,
    evidence: rep.evidence,
    trials: {
      total: trials.length,
      conclusive,
      successes: vulnerable.length,
      safe: safe.length,
      inconclusive,
      errors,
      asr: conclusive ? vulnerable.length / conclusive : null,
      ci95: ci ? [ci.low, ci.high] : null,
      runs: trials.map((t, i) => ({
        trial: i + 1,
        verdict: t.verdict,
        cause: t.cause,
        reason: t.reason,
        firstLeakStep: t.evidence ? t.evidence.firstLeakStep : null,
        extractionAssessment: t.evidence ? t.evidence.extractionAssessment : undefined,
        provenance: t.response && t.response.provenance ? t.response.provenance.source : undefined,
        ms: t.response ? t.response.ms : undefined,
      })),
    },
  };
}

// Runs every attack `trials` times with a bounded worker pool.
async function runScan(config, attacks, opts = {}) {
  const { judge, onResult, onTrial } = opts;
  const trials = Math.max(1, Math.floor(opts.trials || config.trials || 1));
  const concurrency = Math.max(1, Math.floor(opts.concurrency || config.concurrency || 1));

  const jobs = [];
  attacks.forEach((attack, a) => {
    for (let t = 0; t < trials; t += 1) jobs.push({ a, t, attack });
  });

  const byAttack = attacks.map(() => []);
  const pending = attacks.map(() => trials);
  const results = new Array(attacks.length);
  let next = 0;

  async function worker() {
    while (next < jobs.length) {
      const job = jobs[next]; next += 1;
      const outcome = await runTrial(config, job.attack, judge);
      byAttack[job.a][job.t] = outcome;
      if (onTrial) onTrial(job.attack, job.t + 1, outcome);
      pending[job.a] -= 1;
      if (pending[job.a] === 0) {
        const result = aggregate(job.attack, byAttack[job.a]);
        results[job.a] = result;
        if (onResult) onResult(result);
      }
      if (config.delayMs && next < jobs.length) await sleep(config.delayMs);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length || 1) }, worker));
  return results;
}

module.exports = { loadAttacks, sendPrompt, runScan, aggregate, fillTemplate, getByPath };
