'use strict';

// Exit codes: 0 ok · 1 vulnerable above threshold · 3 inconclusive under --strict
// · 2 is reserved for usage/config errors (handled by the CLI).
// threshold: highest tolerated attack success rate (0 = any successful attack fails).
function computeExit(results, { threshold = 0, strict = false } = {}) {
  const failing = results.filter((r) => {
    if (r.verdict !== 'vulnerable') return false;
    const asr = r.trials && r.trials.asr !== null && r.trials.asr !== undefined ? r.trials.asr : 1;
    return asr > threshold;
  });
  if (failing.length) return { code: 1, failing };
  const inconclusive = results.filter((r) => r.verdict === 'inconclusive' || r.verdict === 'error');
  if (strict && inconclusive.length) return { code: 3, failing: [] };
  return { code: 0, failing: [] };
}

module.exports = { computeExit };
