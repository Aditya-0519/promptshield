'use strict';

const fs = require('fs');
const path = require('path');
const { transportName, defaultUrl, keyEnvNames } = require('./transports');
const { isLocalUrl } = require('./transports/util');
const { templateUses } = require('./template');

const KNOWN_KEYS = [
  'transport', 'provider', 'url', 'startUrl', 'method', 'headers', 'model', 'apiKey', 'apiKeyEnv',
  'params', 'maxTokens', 'anthropicVersion',
  'bodyTemplate', 'startBodyTemplate', 'responsePath', 'stream',
  'systemPrompt', 'systemPromptFile', 'sendSystemPrompt', 'systemPromptThreshold',
  'secrets', 'allow', 'refusalAware',
  'trials', 'concurrency', 'threshold', 'delayMs', 'timeoutMs', 'retries', 'retryBaseMs',
  'maxResponseBytes', 'authorized',
  'requireProvenance', 'provenanceHeader', 'provenancePath',
];

// ${VAR} or ${VAR:-default} anywhere in any string value.
function expandEnv(value, missing = new Set(), env = process.env) {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (m, name, dflt) => {
      if (env[name] !== undefined && env[name] !== '') return env[name];
      if (dflt !== undefined) return dflt;
      missing.add(name);
      return m;
    });
  }
  if (Array.isArray(value)) return value.map((v) => expandEnv(v, missing, env));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = expandEnv(v, missing, env);
    return out;
  }
  return value;
}

function loadConfig(configPath) {
  const text = fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, '');
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`Config ${configPath} is not valid JSON: ${err.message}`);
  }
  return resolveConfig(raw, path.dirname(configPath));
}

// Expands environment variables, loads systemPromptFile, normalises names.
function resolveConfig(raw, baseDir = process.cwd()) {
  const missing = new Set();
  const config = expandEnv(raw, missing);
  if (missing.size) {
    throw new Error(
      `Config refers to environment variable(s) that are not set: ${[...missing].join(', ')}. ` +
      'Export them before scanning (secrets are never stored in the config file).'
    );
  }
  if (config.provider && !config.transport) config.transport = config.provider;
  if (config.systemPromptFile && !config.systemPrompt) {
    const file = path.resolve(baseDir, config.systemPromptFile);
    if (!fs.existsSync(file)) throw new Error(`systemPromptFile not found: ${file}`);
    config.systemPrompt = fs.readFileSync(file, 'utf8');
  }
  return config;
}

// Returns { errors: [], warnings: [] }.
function validateConfig(config, attacks = []) {
  const errors = [];
  const warnings = [];
  const name = transportName(config);

  for (const key of Object.keys(config)) {
    if (!KNOWN_KEYS.includes(key) && !key.startsWith('_')) {
      warnings.push(`Unknown config key "${key}" (ignored). Check for a typo.`);
    }
  }
  if (!name) {
    errors.push(`transport "${config.transport}" is not supported. Use http, openai, anthropic, gemini or ollama.`);
    return { errors, warnings };
  }

  const url = config.url || defaultUrl(config);
  const validateTargetUrl = (value, field) => {
    if (!value) { errors.push(`\"${field}\" is required for the http transport.`); return; }
    try {
      const parsed = new URL(value);
      if (!['http:', 'https:'].includes(parsed.protocol)) errors.push(`\"${field}\" must use http or https.`);
      if (parsed.username || parsed.password) errors.push(`\"${field}\" must not contain embedded credentials.`);
    } catch (_) { errors.push(`\"${field}\" is not a valid URL: ${value}`); }
  };
  validateTargetUrl(url, 'url');
  if (config.startUrl !== undefined) validateTargetUrl(config.startUrl, 'startUrl');

  if (name === 'http') {
    if (!config.bodyTemplate || typeof config.bodyTemplate !== 'object') {
      errors.push('"bodyTemplate" is required for the http transport (use {{prompt}} where the attack text goes).');
    } else if (!templateUses(config.bodyTemplate, 'prompt') && !templateUses(config.bodyTemplate, 'messages')) {
      errors.push('"bodyTemplate" must contain {{prompt}} or {{messages}}; otherwise every attack sends the same request.');
    }
    if (!config.responsePath) {
      warnings.push('No "responsePath": the whole response body will be judged. Set it (e.g. "reply" or "choices.0.message.content") for accurate results.');
    }
    const multi = attacks.some((a) => Array.isArray(a.steps) && a.steps.length > 1);
    if (multi && !templateUses(config.bodyTemplate, 'messages') && !templateUses(config.bodyTemplate, 'sessionId')) {
      warnings.push(
        'Multi-turn attacks are selected but bodyTemplate has neither {{messages}} nor {{sessionId}}. ' +
        'Each turn will reach your app as an unrelated single message. Add one of them.'
      );
    }
  } else if (!config.model) {
    errors.push(`"model" is required for the ${name} transport.`);
  }

  if (name !== 'http' && name !== 'ollama' && !isLocalUrl(url || '')) {
    const hasAuth = config.apiKey || (config.headers && Object.keys(config.headers).some((h) => /^(authorization|x-api-key|x-goog-api-key)$/i.test(h))) ||
      (config.apiKeyEnv && process.env[config.apiKeyEnv]) || keyEnvNames(config).some((n) => process.env[n]);
    if (!hasAuth) errors.push(`No API key found. Set ${keyEnvNames(config).join(' or ') || 'apiKey'} in the environment.`);
  }

  const num = (key, min, max) => {
    if (config[key] === undefined) return;
    if (!Number.isFinite(config[key]) || config[key] < min || config[key] > max) {
      errors.push(`"${key}" must be a number between ${min} and ${max}.`);
    }
  };
  num('trials', 1, 1000);
  num('concurrency', 1, 32);
  num('threshold', 0, 1);
  num('delayMs', 0, 3600000);
  num('timeoutMs', 1, 3600000);
  num('retries', 0, 10);
  num('systemPromptThreshold', 0.01, 1);

  if (config.secrets !== undefined && !(Array.isArray(config.secrets) && config.secrets.every((s) => typeof s === 'string'))) {
    errors.push('"secrets" must be an array of strings.');
  }
  if (config.allow !== undefined && !(Array.isArray(config.allow) && config.allow.every((s) => typeof s === 'string'))) {
    errors.push('"allow" must be an array of strings.');
  }
  if (!(config.secrets || []).some((s) => String(s).trim()) && !config.systemPrompt) {
    warnings.push(
      'No "secrets" (canaries) and no "systemPrompt" configured. System-prompt-leak attacks cannot be judged ' +
      'and will be reported INCONCLUSIVE. Run "promptshield init" to generate canaries.'
    );
  }
  return { errors, warnings };
}

module.exports = { loadConfig, resolveConfig, validateConfig, expandEnv, KNOWN_KEYS };
