'use strict';

// Template helpers shared by every transport.

function getByPath(obj, p) {
  if (!p) return obj;
  return String(p)
    .split('.')
    .reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

const safeParse = (raw) => {
  try {
    return JSON.parse(raw);
  } catch (_) {
    return undefined;
  }
};

// Back-compatible: replaces {{prompt}} only.
function fillTemplate(value, prompt) {
  return renderTemplate(value, { prompt });
}

// Single-pass renderer. A string that is exactly "{{messages}}" becomes the
// whole conversation array; every other {{name}} becomes a string. Single pass
// means text that is inserted (e.g. an attack prompt) is never re-expanded.
function renderTemplate(value, vars) {
  if (typeof value === 'string') {
    if (value === '{{messages}}' && Array.isArray(vars.messages)) {
      return vars.messages.map((m) => ({ ...m }));
    }
    return value.replace(/\{\{(\w+)\}\}/g, (match, key) =>
      Object.prototype.hasOwnProperty.call(vars, key) && typeof vars[key] !== 'object'
        ? String(vars[key])
        : match
    );
  }
  if (Array.isArray(value)) return value.map((v) => renderTemplate(v, vars));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = renderTemplate(v, vars);
    return out;
  }
  return value;
}

function templateUses(template, name) {
  return JSON.stringify(template || {}).includes(`{{${name}}}`);
}

// Replace {{previousResponse}} and {{response1}}.. in a multi-turn step.
function fillStepTemplate(template, previousResponse, responses) {
  let result = String(template).split('{{previousResponse}}').join(previousResponse || '');
  responses.forEach((response, index) => {
    result = result.split(`{{response${index + 1}}}`).join(response);
  });
  return result;
}

// Turns whatever a provider returns at the response path into plain text.
// Handles strings, arrays of content parts (OpenAI, Anthropic, Gemini) and objects.
function flattenText(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          if (item.type && !['text', 'output_text'].includes(item.type)) return '';
          return typeof item.text === 'string' ? item.text : '';
        }
        return '';
      })
      .join('');
  }
  if (typeof value === 'object') {
    return typeof value.text === 'string' ? value.text : JSON.stringify(value);
  }
  return String(value);
}

// Streaming bodies: SSE ("data: {...}") or NDJSON. Returns the joined text.
function collectStream(raw, responsePath) {
  const known = [
    'choices.0.delta.content',
    'delta.text',
    'candidates.0.content.parts',
    'message.content',
    'response',
  ];
  let out = '';
  for (const lineRaw of String(raw).split(/\r?\n/)) {
    let line = lineRaw.trim();
    if (!line || line.startsWith(':') || line.startsWith('event:')) continue;
    if (line.startsWith('data:')) line = line.slice(5).trim();
    if (!line || line === '[DONE]') continue;
    const evt = safeParse(line);
    if (!evt || typeof evt !== 'object') continue;
    const paths = responsePath ? [responsePath, ...known] : known;
    for (const p of paths) {
      const piece = flattenText(getByPath(evt, p));
      if (typeof piece === 'string' && piece) {
        out += piece;
        break;
      }
    }
  }
  return out;
}

module.exports = {
  getByPath,
  safeParse,
  fillTemplate,
  renderTemplate,
  templateUses,
  fillStepTemplate,
  flattenText,
  collectStream,
};
