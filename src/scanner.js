const fs = require('fs');
const path = require('path');

function loadAttacks(dir, categories) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  let attacks = [];
  for (const f of files) {
    const data = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    attacks = attacks.concat(data);
  }
  if (categories && categories.length) {
    attacks = attacks.filter((a) => categories.includes(a.category));
  }
  return attacks;
}

// Replace {{prompt}} anywhere inside the request body template.
function fillTemplate(value, prompt) {
  if (typeof value === 'string') return value.split('{{prompt}}').join(prompt);
  if (Array.isArray(value)) return value.map((v) => fillTemplate(v, prompt));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = fillTemplate(v, prompt);
    return out;
  }
  return value;
}

function getByPath(obj, p) {
  if (!p) return obj;
  return p.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

async function sendPrompt(config, prompt) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs || 30000);
  const started = Date.now();
  try {
    const res = await fetch(config.url, {
      method: config.method || 'POST',
      headers: config.headers || { 'Content-Type': 'application/json' },
      body: JSON.stringify(fillTemplate(config.bodyTemplate, prompt)),
      signal: controller.signal,
    });
    const raw = await res.text();
    let text = raw;
    try {
      const extracted = getByPath(JSON.parse(raw), config.responsePath);
      text = typeof extracted === 'string' ? extracted : JSON.stringify(extracted);
    } catch (_) {
      /* response was not JSON, keep the raw text */
    }
    return { ok: res.ok, status: res.status, text: text ?? '', ms: Date.now() - started };
  } catch (err) {
    return { ok: false, status: 0, text: '', error: err.message, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runScan(config, attacks, { judge, onResult } = {}) {
  const results = [];
  for (const attack of attacks) {
    const response = await sendPrompt(config, attack.prompt);
    let verdict;
    if (response.error || !response.ok) {
      verdict = { verdict: 'error', reason: response.error || `HTTP ${response.status}` };
    } else {
      verdict = await judge(attack, response.text, config);
    }
    const result = { attack, response, ...verdict };
    results.push(result);
    if (onResult) onResult(result);
    if (config.delayMs) await sleep(config.delayMs);
  }
  return results;
}

module.exports = { loadAttacks, sendPrompt, runScan, fillTemplate, getByPath };
