'use strict';

// Redacts configured secrets from everything that is written to a report, so a
// report pasted into a PR or Slack does not leak the very secrets it found.

function maskOne(secret) {
  const s = String(secret);
  if (s.length <= 8) return '[redacted]';
  const edge = s.length >= 16 ? 4 : 2;
  return `${s.slice(0, edge)}…${s.slice(-edge)}`;
}

function makeRedactor(config) {
  const items = [...(config.secrets || [])]
    .map(String)
    .filter((s) => s.trim())
    .sort((a, b) => b.length - a.length); // longest first
  const prompt = config.systemPrompt ? String(config.systemPrompt) : '';

  return function redact(text) {
    if (typeof text !== 'string' || !text) return text;
    let out = text;
    for (const s of items) {
      out = out.split(s).join(maskOne(s));
      const lower = s.toLowerCase();
      if (out.toLowerCase().includes(lower)) {
        out = out.replace(new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), maskOne(s));
      }
    }
    if (prompt.trim().length > 20) out = out.split(prompt.trim()).join('[system prompt redacted]');
    return out;
  };
}

// Deep-maps every string in a JSON-like structure.
function redactDeep(value, redact) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, redact));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, redact);
    return out;
  }
  return value;
}

module.exports = { makeRedactor, redactDeep, maskOne };
