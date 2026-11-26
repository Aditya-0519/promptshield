const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { extractProvenance, combineProvenance } = require('./provenance');

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
  if (typeof value === 'string') {
    return value.split('{{prompt}}').join(prompt);
  }

  if (Array.isArray(value)) {
    return value.map((v) => fillTemplate(v, prompt));
  }

  if (value && typeof value === 'object') {
    const out = {};

    for (const [k, v] of Object.entries(value)) {
      out[k] = fillTemplate(v, prompt);
    }

    return out;
  }

  return value;
}

function getByPath(obj, p) {
  if (!p) return obj;

  return p.split('.').reduce(
    (acc, key) => (acc == null ? undefined : acc[key]),
    obj
  );
}

// Replace session ID before inserting the attack prompt.
const withSessionId = (template, sessionId) =>
  JSON.parse(
    JSON.stringify(template)
      .split('{{sessionId}}')
      .join(sessionId)
  );

async function postJson(config, url, body) {
  const controller = new AbortController();

  const timeoutMs = config.timeoutMs || 30000;
  let timedOut = false;

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const started = Date.now();

  try {
    const res = await fetch(url, {
      method: config.method || 'POST',
      headers: config.headers || {
        'Content-Type': 'application/json',
      },
      body,
      signal: controller.signal,
    });

    const raw = await res.text();

    return {
      ok: res.ok,
      status: res.status,
      raw,
      headers: res.headers,
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      raw: '',
      error: timedOut ? `Request timed out after ${timeoutMs}ms` : err.message,
      timedOut,
      ms: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

const describeFailure = (r) =>
  r.error ||
  `HTTP ${r.status}: ${r.raw.replace(/\s+/g, ' ').slice(0, 200)}`;

const causeOf = (r) =>
  r.timedOut ? 'timeout' : r.status === 0 ? 'network_error' : 'http_error';

const safeParse = (raw) => {
  try {
    return JSON.parse(raw);
  } catch (_) {
    return undefined;
  }
};

async function sendPrompt(config, prompt) {
  const sessionId = `scan-${crypto.randomUUID()}`;
  const provenanceParts = [];

  // Step 1: Start a fresh interview if configured.
  if (config.startBodyTemplate) {
    const start = await postJson(
      config,
      config.startUrl || config.url,
      JSON.stringify(
        fillTemplate(
          withSessionId(config.startBodyTemplate, sessionId),
          ''
        )
      )
    );

    if (start.error || !start.ok) {
      return {
        ok: false,
        status: start.status,
        text: start.raw,
        error: `Start request failed - ${describeFailure(start)}`,
        cause: causeOf(start),
        step: 'start',
        ms: start.ms,
      };
    }

    provenanceParts.push(
      extractProvenance(start.headers, safeParse(start.raw), config)
    );
  }

  // Step 2: Submit the attack using the same session ID.
  const res = await postJson(
    config,
    config.url,
    JSON.stringify(
      fillTemplate(
        withSessionId(config.bodyTemplate, sessionId),
        prompt
      )
    )
  );

  if (res.error || !res.ok) {
    return {
      ok: false,
      status: res.status,
      text: res.raw,
      error: describeFailure(res),
      cause: causeOf(res),
      step: 'attack',
      ms: res.ms,
    };
  }

  const parsed = safeParse(res.raw);
  provenanceParts.push(extractProvenance(res.headers, parsed, config));

  let text = res.raw;

  if (parsed !== undefined) {
    const extracted = getByPath(parsed, config.responsePath);

    text =
      typeof extracted === 'string'
        ? extracted
        : JSON.stringify(extracted);
  }

  return {
    ok: true,
    status: res.status,
    text: text ?? '',
    ms: res.ms,
    provenance: combineProvenance(provenanceParts),
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runScan(config, attacks, { judge, onResult } = {}) {
  const results = [];

  for (const attack of attacks) {
    const response = await sendPrompt(config, attack.prompt);

    let verdict;

    if (response.error || !response.ok) {
      // HTTP error, timeout or network failure: the attack was never really
      // tested, so the result is inconclusive, never safe.
      verdict = {
        verdict: 'inconclusive',
        cause: response.cause || 'http_error',
        reason: response.error || `HTTP ${response.status}`,
      };
    } else {
      verdict = await judge(attack, response.text, config, response);
    }

    const result = {
      attack,
      response,
      ...verdict,
    };

    results.push(result);

    if (onResult) onResult(result);

    if (config.delayMs) {
      await sleep(config.delayMs);
    }
  }

  return results;
}

module.exports = {
  loadAttacks,
  sendPrompt,
  runScan,
  fillTemplate,
  getByPath,
};