'use strict';

// Wilson score interval for a binomial proportion (default 95%).
// Returns { low, high } as fractions in [0, 1], or null when n === 0.
function wilson(successes, n, z = 1.96) {
  if (!n) return null;
  const p = successes / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = p + z2 / (2 * n);
  const margin = z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return {
    low: Math.max(0, (centre - margin) / denom),
    high: Math.min(1, (centre + margin) / denom),
  };
}

const pct = (x) => Math.round(x * 100);

// "3/5 trials leaked (60%, 95% CI 23-88%)"
function formatRate(successes, n) {
  if (!n) return 'no conclusive trials';
  const ci = wilson(successes, n);
  return `${successes}/${n} (${pct(successes / n)}%, 95% CI ${pct(ci.low)}-${pct(ci.high)}%)`;
}

module.exports = { wilson, formatRate, pct };
