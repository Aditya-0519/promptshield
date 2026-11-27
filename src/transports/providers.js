'use strict';

// Provider transports. Each one knows how to build ONE request from the full
// conversation so far and how to pull the assistant text out of the reply.
// Multi-turn is therefore identical for every provider: the conversation is
// replayed on every request (these APIs are stateless).

const { withSystem, baseHeaders, envKey } = require('./util');
const { getByPath, flattenText } = require('../template');

const extractAt = (path) => (parsed, config) =>
  flattenText(getByPath(parsed, config.responsePath || path));

const openai = {
  name: 'openai',
  label: 'OpenAI-compatible',
  keyEnv: ['OPENAI_API_KEY'],
  defaultUrl: () => 'https://api.openai.com/v1/chat/completions',
  buildRequest(config, { messages }) {
    const key = envKey(config, ...this.keyEnv);
    return {
      url: config.url || this.defaultUrl(config),
      headers: baseHeaders(config, key ? { Authorization: `Bearer ${key}` } : {}),
      body: JSON.stringify({
        model: config.model,
        messages: withSystem(config, messages),
        stream: false,
        ...(config.params || {}),
      }),
    };
  },
  extract: extractAt('choices.0.message.content'),
};

const anthropic = {
  name: 'anthropic',
  label: 'Anthropic',
  keyEnv: ['ANTHROPIC_API_KEY'],
  defaultUrl: () => 'https://api.anthropic.com/v1/messages',
  buildRequest(config, { messages }) {
    const key = envKey(config, ...this.keyEnv);
    return {
      url: config.url || this.defaultUrl(config),
      headers: baseHeaders(config, {
        ...(key ? { 'x-api-key': key } : {}),
        'anthropic-version': config.anthropicVersion || '2023-06-01',
      }),
      body: JSON.stringify({
        model: config.model,
        max_tokens: config.maxTokens || 1024,
        ...(config.systemPrompt && config.sendSystemPrompt !== false
          ? { system: String(config.systemPrompt) }
          : {}),
        messages,
        ...(config.params || {}),
      }),
    };
  },
  extract: extractAt('content'),
};

const gemini = {
  name: 'gemini',
  label: 'Gemini',
  keyEnv: ['GEMINI_API_KEY', 'GOOGLE_API_KEY'],
  defaultUrl: (config) =>
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
      config.model || 'gemini-2.5-flash'
    )}:generateContent`,
  buildRequest(config, { messages }) {
    const key = envKey(config, ...this.keyEnv);
    const url = String(config.url || this.defaultUrl(config)).replace('{model}', config.model || '');
    return {
      url,
      headers: baseHeaders(config, key ? { 'x-goog-api-key': key } : {}),
      body: JSON.stringify({
        ...(config.systemPrompt && config.sendSystemPrompt !== false
          ? { systemInstruction: { parts: [{ text: String(config.systemPrompt) }] } }
          : {}),
        contents: messages.map((m) => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }],
        })),
        ...(config.params || {}),
      }),
    };
  },
  extract: extractAt('candidates.0.content.parts'),
};

const ollama = {
  name: 'ollama',
  label: 'Ollama',
  defaultUrl: () => 'http://localhost:11434/api/chat',
  buildRequest(config, { messages }) {
    return {
      url: config.url || this.defaultUrl(config),
      headers: baseHeaders(config, {}),
      body: JSON.stringify({
        model: config.model,
        messages: withSystem(config, messages),
        stream: false,
        ...(config.params || {}),
      }),
    };
  },
  extract: extractAt('message.content'),
};

module.exports = { openai, anthropic, gemini, ollama };
