// Unit tests for src/provenance.js (pure functions, no network).
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeSource,
  extractProvenance,
  combineProvenance,
  gateProvenance,
} = require('../src/provenance');

const headers = (obj) => new Headers(obj);

describe('extractProvenance', () => {
  it('reads the X-AI-Provenance header', () => {
    assert.equal(extractProvenance(headers({ 'X-AI-Provenance': 'live' }), undefined).source, 'live');
  });

  it('reads provenance.source from the body', () => {
    assert.equal(extractProvenance(headers({}), { provenance: { source: 'mock' } }).source, 'mock');
  });

  it('returns undefined source when nothing is reported', () => {
    assert.equal(extractProvenance(headers({}), { reply: 'x' }).source, undefined);
  });

  it('unknown values are never treated as live', () => {
    assert.equal(extractProvenance(headers({ 'X-AI-Provenance': 'maybe' }), undefined).source, 'unknown');
  });

  it('header/body disagreement uses the worse value', () => {
    const r = extractProvenance(headers({ 'X-AI-Provenance': 'live' }), { provenance: { source: 'fallback' } });
    assert.equal(r.source, 'fallback');
  });

  it('honors custom header name and body path', () => {
    const cfg = { provenanceHeader: 'X-Source', provenancePath: 'meta.ai' };
    assert.equal(extractProvenance(headers({ 'X-Source': 'fallback' }), undefined, cfg).source, 'fallback');
    assert.equal(extractProvenance(headers({}), { meta: { ai: 'mock' } }, cfg).source, 'mock');
  });

  it('keeps fixed reason codes from the body', () => {
    const r = extractProvenance(headers({}), { provenance: { source: 'fallback', reasons: ['quota_or_rate_limit'] } });
    assert.deepEqual(r.reasons, ['quota_or_rate_limit']);
  });
});

describe('combineProvenance (worst-wins)', () => {
  const p = (source) => ({ source });

  it('live + live = live', () => assert.equal(combineProvenance([p('live'), p('live')]).source, 'live'));
  it('live + fallback = fallback', () => assert.equal(combineProvenance([p('live'), p('fallback')]).source, 'fallback'));
  it('live + mock = mock', () => assert.equal(combineProvenance([p('live'), p('mock')]).source, 'mock'));
  it('live + missing = missing', () => assert.equal(combineProvenance([p('live'), p(undefined)]).source, undefined));
  it('mock + missing = mock', () => assert.equal(combineProvenance([p('mock'), p(undefined)]).source, 'mock'));
  it('empty = missing', () => assert.equal(combineProvenance([]).source, undefined));
});

describe('gateProvenance', () => {
  it('live passes', () => assert.equal(gateProvenance({ source: 'live' }, { requireProvenance: true }), null));

  it('missing + requireProvenance => provenance_missing', () => {
    assert.equal(gateProvenance({ source: undefined }, { requireProvenance: true }).cause, 'provenance_missing');
  });

  it('missing without requireProvenance passes (legacy targets)', () => {
    assert.equal(gateProvenance({ source: undefined }, {}), null);
  });

  for (const source of ['mock', 'fallback', 'none', 'unknown']) {
    it(`${source} => provenance_not_live, even without requireProvenance`, () => {
      assert.equal(gateProvenance({ source }, {}).cause, 'provenance_not_live');
    });
  }

  it('normalizeSource handles case and whitespace', () => {
    assert.equal(normalizeSource(' LIVE '), 'live');
  });
});