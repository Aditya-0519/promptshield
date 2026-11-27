'use strict';

// Runs ONE attack (single- or multi-turn) against ANY target through the
// transport interface. Every step is a real request with the conversation so
// far; nothing is ever sent as an empty prompt.

const { request, describeFailure, causeOf } = require('./http');
const { extractProvenance, combineProvenance } = require('./provenance');
const { fillStepTemplate } = require('./template');
const { createTransport } = require('./transports');

function stepsOf(attack) {
  if (Array.isArray(attack.steps) && attack.steps.length) return attack.steps.map(String);
  if (typeof attack.prompt === 'string' && attack.prompt.trim()) return [attack.prompt];
  return [];
}

async function converse(config, promptOrAttack) {
  const attack = promptOrAttack && typeof promptOrAttack === 'object'
    ? promptOrAttack
    : { prompt: promptOrAttack };
  const steps = stepsOf(attack);

  if (!steps.length) {
    return {
      ok: false, status: 0, text: '', steps: [],
      error: `Attack ${attack.id || ''} has neither "prompt" nor "steps"; nothing was sent`,
      cause: 'invalid_attack', ms: 0,
    };
  }

  const transport = createTransport(config);
  const session = transport.newSession();
  const multi = steps.length > 1;

  const startFailure = await transport.start(config, session);
  if (startFailure) return { ...startFailure, steps: [], provenance: combineProvenance(session.provenance) };

  const history = [];
  const done = [];
  const transcript = [];
  let previous = '';
  let totalMs = 0;

  const fail = (i, res, error, cause) => ({
    ok: false,
    status: res.status,
    text: transcript.join('\n\n'),
    steps: done,
    error: multi ? `${transport.label} step ${i + 1} failed - ${error}` : error,
    cause,
    step: i + 1,
    ms: totalMs,
    provenance: combineProvenance(session.provenance),
  });

  for (let i = 0; i < steps.length; i += 1) {
    const prompt = fillStepTemplate(steps[i], previous, done.map((s) => s.text));
    history.push({ role: 'user', content: prompt });

    const req = transport.buildRequest(config, session, { messages: history, prompt });
    const res = await request(config, req);
    totalMs += res.ms;

    if (res.error || !res.ok) return fail(i, res, describeFailure(res), causeOf(res));

    const { parsed, text } = transport.extract(config, res);
    if (typeof text !== 'string') {
      const why = transport.invalidMessage(config);
      const out = fail(i, res, `invalid response: ${why}`, 'invalid_response');
      if (!multi) out.error = `Invalid response: ${why}`;
      return out;
    }

    history.push({ role: 'assistant', content: text });
    previous = text;
    done.push({ prompt, text, status: res.status, ms: res.ms, truncated: res.truncated || undefined });
    transcript.push(`Step ${i + 1} - User:\n${prompt}\n\nStep ${i + 1} - Assistant:\n${text}`);
    session.provenance.push(extractProvenance(res.headers, parsed, config));
  }

  return {
    ok: true,
    status: 200,
    // Single turn: the reply itself. Multi-turn: the readable transcript.
    text: multi ? transcript.join('\n\n') : done[0].text,
    steps: done,
    ms: totalMs,
    provenance: combineProvenance(session.provenance),
  };
}

module.exports = { converse, stepsOf };
