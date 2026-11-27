'use strict';

// One HTTP request with: timeout, response-size cap, and retry with backoff
// on 429 / 502 / 503 / 504 / connection errors. Timeouts are never retried.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const RETRY_STATUS = new Set([429, 502, 503, 504]);
const DEFAULT_MAX_BYTES = 2_000_000;

async function readCapped(res, maxBytes) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    const t = await res.text();
    return t.length > maxBytes
      ? { raw: t.slice(0, maxBytes), truncated: true }
      : { raw: t, truncated: false };
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let raw = '';
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.length;
    raw += decoder.decode(value, { stream: true });
    if (bytes > maxBytes) {
      truncated = true;
      try { await reader.cancel(); } catch (_) { /* ignore */ }
      break;
    }
  }
  raw += decoder.decode();
  if (raw.length > maxBytes) { raw = raw.slice(0, maxBytes); truncated = true; }
  return { raw, truncated };
}

async function requestOnce({ url, method, headers, body, timeoutMs, maxBytes }) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const started = Date.now();
  try {
    // Do not follow redirects: a redirect could silently send scan payloads or
    // credentials to a different host than the one the user authorized.
    const res = await fetch(url, { method, headers, body, signal: controller.signal, redirect: 'error' });
    const { raw, truncated } = await readCapped(res, maxBytes);
    return {
      ok: res.ok,
      status: res.status,
      raw,
      truncated,
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

function retryDelay(res, attempt, baseMs) {
  const retryAfter = res.headers && typeof res.headers.get === 'function'
    ? Number(res.headers.get('retry-after'))
    : NaN;
  if (Number.isFinite(retryAfter) && retryAfter >= 0) return Math.min(retryAfter * 1000, 10000);
  const exp = baseMs * 2 ** attempt;
  return Math.min(exp + Math.floor(Math.random() * baseMs), 10000);
}

async function request(config, { url, method, headers, body }) {
  const opts = {
    url,
    method: method || config.method || 'POST',
    headers: headers || config.headers || { 'Content-Type': 'application/json' },
    body,
    timeoutMs: config.timeoutMs || 30000,
    maxBytes: config.maxResponseBytes || DEFAULT_MAX_BYTES,
  };
  const retries = Number.isInteger(config.retries) ? config.retries : 2;
  const baseMs = config.retryBaseMs || 250;
  let res;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    res = await requestOnce(opts);
    const retryable = RETRY_STATUS.has(res.status) || (res.status === 0 && !res.timedOut);
    if (!retryable || attempt === retries) break;
    await sleep(retryDelay(res, attempt, baseMs));
  }
  return res;
}

const describeFailure = (r) =>
  r.error || `HTTP ${r.status}: ${String(r.raw || '').replace(/\s+/g, ' ').slice(0, 200)}`;

const causeOf = (r) =>
  r.timedOut ? 'timeout' : r.status === 0 ? 'network_error' : 'http_error';

module.exports = { request, describeFailure, causeOf, sleep };
