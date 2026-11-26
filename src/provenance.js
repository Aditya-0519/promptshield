// Reads and evaluates AI "provenance" reported by a target.
//
// A target that supports it says whether a response came from a live model
// call, an intentional mock, or a mock fallback after a provider failure:
//   header  X-AI-Provenance: live | mock | fallback | none
//   body    provenance.source (same values)
//
// Config (all optional):
//   provenanceHeader   header name   (default "x-ai-provenance")
//   provenancePath     body dot path (default "provenance.source")
//   requireProvenance  true => a response without provenance is INCONCLUSIVE

const KNOWN = new Set(['live', 'mock', 'fallback', 'none']);

// Higher = worse. Used for worst-wins combination.
const BADNESS = { fallback: 4, mock: 3, unknown: 2, none: 1, live: 0 };

function normalizeSource(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const s = String(value).trim().toLowerCase();
  return KNOWN.has(s) ? s : 'unknown';
}

function dig(obj, p) {
  return String(p)
    .split('.')
    .reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

const worst = (sources) =>
  sources.slice().sort((a, b) => BADNESS[b] - BADNESS[a])[0];

// One HTTP response -> { source, reasons? }. source is undefined when missing.
function extractProvenance(headers, body, config = {}) {
  const headerName = String(config.provenanceHeader || 'x-ai-provenance').toLowerCase();
  const bodyPath = config.provenancePath || 'provenance.source';

  const fromHeader =
    headers && typeof headers.get === 'function' ? headers.get(headerName) : undefined;
  const fromBody = body && typeof body === 'object' ? dig(body, bodyPath) : undefined;

  const found = [normalizeSource(fromHeader), normalizeSource(fromBody)].filter(Boolean);
  if (found.length === 0) return { source: undefined };

  // If header and body disagree, trust the worse one.
  const out = { source: worst(found) };

  const reasons = body && body.provenance && body.provenance.reasons;
  if (Array.isArray(reasons) && reasons.length) {
    out.reasons = reasons.map(String).slice(0, 5);
  }
  return out;
}

// Several HTTP steps (start + attack) -> one overall provenance, worst-wins.
// A step with no provenance can never make the result look better than it is.
function combineProvenance(parts) {
  const list = (parts || []).filter(Boolean);
  const sources = list.map((p) => p.source);
  const defined = sources.filter(Boolean);
  const anyMissing = list.length === 0 || sources.some((s) => s === undefined);

  let source;
  if (defined.length === 0) {
    source = undefined;
  } else {
    const w = worst(defined);
    // A known-bad value always wins; otherwise any missing step means "unknown".
    source = anyMissing && BADNESS[w] < BADNESS.unknown ? undefined : w;
  }

  const reasons = [...new Set(list.flatMap((p) => p.reasons || []))];
  const out = { source, parts: list };
  if (reasons.length) out.reasons = reasons;
  return out;
}

// Returns null when the response may be judged normally, otherwise
// { cause, reason } describing why the result must be INCONCLUSIVE.
function gateProvenance(prov, config = {}) {
  const source = prov && prov.source;

  if (source === 'live') return null;

  if (source === undefined) {
    if (config.requireProvenance) {
      return {
        cause: 'provenance_missing',
        reason:
          'Target did not report response provenance (requireProvenance is enabled), ' +
          'so this response cannot be confirmed as coming from a live model.',
      };
    }
    return null; // legacy target without provenance: judged as before
  }

  const detail = prov.reasons && prov.reasons.length ? `; reasons: ${prov.reasons.join(', ')}` : '';
  return {
    cause: 'provenance_not_live',
    reason:
      `Response was not produced by a live model call (provenance: ${source}${detail}). ` +
      'The attack was not truly tested.',
  };
}

module.exports = { normalizeSource, extractProvenance, combineProvenance, gateProvenance };