'use strict';

const http = require('./http');
const providers = require('./providers');
const crypto = require('crypto');
const { extractProvenance } = require('../provenance');
const { safeParse } = require('../template');

const ALIASES = {
  http: 'http', 'http-template': 'http', generic: 'http',
  openai: 'openai', 'openai-compatible': 'openai', 'openai-compat': 'openai',
  anthropic: 'anthropic', claude: 'anthropic',
  gemini: 'gemini', google: 'gemini',
  ollama: 'ollama', 'ollama-chat': 'ollama',
};

function transportName(config) {
  const raw = String(config.transport || config.provider || 'http').toLowerCase();
  return ALIASES[raw];
}

// Wraps a provider (pure request builder) into the same interface as `http`.
function wrapProvider(p) {
  return {
    name: p.name,
    label: p.label,
    newSession: () => ({ sessionId: `scan-${crypto.randomUUID()}`, provenance: [] }),
    start: async () => null,
    buildRequest: (config, _session, turn) => p.buildRequest(config, turn),
    extract: (config, res) => {
      const parsed = safeParse(res.raw);
      return { parsed, text: parsed === undefined ? undefined : p.extract(parsed, config) };
    },
    invalidMessage: () => 'assistant content was missing from the response',
  };
}

function createTransport(config) {
  const name = transportName(config);
  if (!name) {
    throw new Error(
      `Unknown transport "${config.transport || config.provider}". ` +
      `Use one of: http, openai, anthropic, gemini, ollama.`
    );
  }
  return name === 'http' ? http : wrapProvider(providers[name]);
}

function defaultUrl(config) {
  const name = transportName(config);
  if (!name || name === 'http') return undefined;
  return providers[name].defaultUrl(config);
}

function keyEnvNames(config) {
  const name = transportName(config);
  return name && providers[name] ? providers[name].keyEnv || [] : [];
}

module.exports = { createTransport, transportName, defaultUrl, keyEnvNames, ALIASES, extractProvenance };
