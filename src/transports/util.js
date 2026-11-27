'use strict';

const LOCAL = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|.*\.local)$/i;

function isLocalUrl(url) {
  try {
    return LOCAL.test(new URL(url).hostname);
  } catch (_) {
    return false;
  }
}

// Conversation messages with the optional system prompt in front.
function withSystem(config, history) {
  const sys = config.sendSystemPrompt !== false && config.systemPrompt;
  return sys ? [{ role: 'system', content: String(sys) }, ...history] : history;
}

function baseHeaders(config, defaults) {
  // User headers win over defaults.
  return { 'Content-Type': 'application/json', ...defaults, ...(config.headers || {}) };
}

function envKey(config, ...names) {
  if (config.apiKey) return String(config.apiKey);
  if (config.apiKeyEnv && process.env[config.apiKeyEnv]) return process.env[config.apiKeyEnv];
  for (const n of names) if (process.env[n]) return process.env[n];
  return undefined;
}

module.exports = { isLocalUrl, withSystem, baseHeaders, envKey };
