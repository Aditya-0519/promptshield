'use strict';

const x = (s) => String(s ?? '').replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]))
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');

// JUnit XML: one testsuite per category, one testcase per attack.
// Vulnerable => <failure>. Inconclusive => <skipped> (or <failure> with strict).
function toJunit(results, { strict = false, threshold = 0 } = {}) {
  const suites = new Map();
  for (const r of results) {
    if (!suites.has(r.attack.category)) suites.set(r.attack.category, []);
    suites.get(r.attack.category).push(r);
  }

  const body = [...suites.entries()].map(([category, list]) => {
    const failures = list.filter((r) => isFailure(r, threshold, strict)).length;
    const skipped = list.filter((r) => r.verdict === 'inconclusive' && !strict).length;
    const cases = list.map((r) => {
      const t = r.trials || {};
      const time = ((r.response && r.response.ms) || 0) / 1000;
      let inner = '';
      if (r.verdict === 'vulnerable' && isFailure(r, threshold, strict)) {
        inner = `<failure message="${x(r.reason)}" type="${x(r.attack.severity)}">${x(`ASR ${t.successes}/${t.conclusive}. Fix: ${r.attack.fix || ''}`)}</failure>`;
      } else if (r.verdict === 'inconclusive' || r.verdict === 'error') {
        inner = strict
          ? `<failure message="${x(r.reason)}" type="inconclusive"/>`
          : `<skipped message="${x(r.reason)}"/>`;
      }
      return `    <testcase classname="${x(category)}" name="${x(`${r.attack.id} ${r.attack.name}`)}" time="${time.toFixed(3)}">${inner}</testcase>`;
    }).join('\n');
    return `  <testsuite name="${x(category)}" tests="${list.length}" failures="${failures}" skipped="${skipped}">\n${cases}\n  </testsuite>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="PromptShield">\n${body}\n</testsuites>\n`;
}

function isFailure(r, threshold, strict) {
  if (r.verdict === 'vulnerable') {
    const asr = r.trials && r.trials.asr != null ? r.trials.asr : 1;
    return asr > threshold;
  }
  return strict && (r.verdict === 'inconclusive' || r.verdict === 'error');
}

module.exports = { toJunit };
