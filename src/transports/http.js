'use strict';

// Generic HTTP transport for any app with its own request shape.
//
// Multi-turn works in two ways (pick by what your body template contains):
//   {{messages}}   stateless chat API: the full history is replayed each turn
//   {{sessionId}}  stateful app: only the current {{prompt}} is sent each turn,
//                  with the same session id (and optional startBodyTemplate)

const crypto = require('crypto');
const { request, describeFailure, causeOf } = require('../http');
const { extractProvenance } = require('../provenance');
const {
  renderTemplate, getByPath, safeParse, flattenText, collectStream,
} = require('../template');

const label = 'HTTP';

function transcriptOf(messages) {
  return messages
    .map((m) => `${m.role === 'assistant' ? 'Assistant' : 'User'}: ${m.content}`)
    .join('\n');
}

function newSession() {
  return { sessionId: `scan-${crypto.randomUUID()}`, provenance: [] };
}

async function start(config, session) {
  if (!config.startBodyTemplate) return null;
  const res = await request(config, {
    url: config.startUrl || config.url,
    body: JSON.stringify(
      renderTemplate(config.startBodyTemplate, { sessionId: session.sessionId, prompt: '' })
    ),
  });
  if (res.error || !res.ok) {
    return {
      ok: false,
      status: res.status,
      text: res.raw,
      error: `Start request failed - ${describeFailure(res)}`,
      cause: causeOf(res),
      step: 'start',
      ms: res.ms,
    };
  }
  session.provenance.push(extractProvenance(res.headers, safeParse(res.raw), config));
  return null;
}

function buildRequest(config, session, { messages, prompt }) {
  return {
    url: config.url,
    body: JSON.stringify(
      renderTemplate(config.bodyTemplate, {
        sessionId: session.sessionId,
        prompt,
        messages,
        transcript: transcriptOf(messages),
      })
    ),
  };
}

// Returns { parsed, text } where text is undefined if the reply is unusable.
function extract(config, res) {
  const type = res.headers && res.headers.get ? res.headers.get('content-type') || '' : '';
  if (config.stream || /text\/event-stream|ndjson/i.test(type)) {
    const text = collectStream(res.raw, config.responsePath);
    return { parsed: undefined, text: text || undefined };
  }
  const parsed = safeParse(res.raw);
  if (parsed === undefined) {
    // Not JSON: a plain-text chat endpoint. Use the body as the answer.
    return { parsed, text: res.raw };
  }
  if (!config.responsePath) return { parsed, text: res.raw };
  return { parsed, text: flattenText(getByPath(parsed, config.responsePath)) };
}

module.exports = {
  name: 'http', label, newSession, start, buildRequest, extract,
  invalidMessage: (config) =>
    `responsePath "${config.responsePath}" was not found in the response, so there is no assistant text to judge`,
};
