const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function summarize(results) {
  const vulnerable = results.filter((r) => r.verdict === 'vulnerable');
  const safe = results.filter((r) => r.verdict === 'safe');
  const errors = results.filter((r) => r.verdict === 'error');
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of vulnerable) bySeverity[r.attack.severity] = (bySeverity[r.attack.severity] || 0) + 1;
  const score = results.length ? Math.round((safe.length / (results.length - errors.length || 1)) * 100) : 0;
  return { total: results.length, vulnerable: vulnerable.length, safe: safe.length, errors: errors.length, bySeverity, score };
}

function renderHtml(results, meta) {
  const s = summarize(results);
  const sorted = [...results].sort((a, b) => {
    const av = a.verdict === 'vulnerable' ? 0 : 1;
    const bv = b.verdict === 'vulnerable' ? 0 : 1;
    if (av !== bv) return av - bv;
    return (SEV_ORDER[a.attack.severity] ?? 9) - (SEV_ORDER[b.attack.severity] ?? 9);
  });

  const rows = sorted
    .map((r) => {
      const cls = r.verdict;
      return `
    <details class="finding ${cls}">
      <summary>
        <span class="badge ${cls}">${esc(r.verdict.toUpperCase())}</span>
        <span class="sev ${esc(r.attack.severity)}">${esc(r.attack.severity)}</span>
        <strong>${esc(r.attack.id)}</strong> ${esc(r.attack.name)}
      </summary>
      <div class="body">
        <p><b>Category:</b> ${esc(r.attack.category)}</p>
        <p><b>Why:</b> ${esc(r.reason)}</p>
        <p><b>Attack prompt:</b></p><pre>${esc(r.attack.prompt)}</pre>
        <p><b>Target response:</b></p><pre>${esc(r.response.text || r.response.error || '(empty)')}</pre>
        ${r.verdict === 'vulnerable' ? `<p><b>How to fix:</b> ${esc(r.attack.fix)}</p>` : ''}
      </div>
    </details>`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PromptShield report</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--card:#f6f6f7;--line:#dcdce0;--bad:#c0392b;--ok:#1e8449;--warn:#b9770e}
@media(prefers-color-scheme:dark){:root{--bg:#161618;--fg:#ececec;--card:#222226;--line:#38383d;--bad:#ff6b5b;--ok:#4cc67f;--warn:#f0b04a}}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:900px;margin-inline:auto}
h1{margin:0 0 4px} .meta{opacity:.7;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card .n{font-size:28px;font-weight:700}
.bad{color:var(--bad)} .ok{color:var(--ok)}
.finding{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--card)}
.finding summary{padding:10px 12px;cursor:pointer;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.body{padding:0 14px 12px}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;margin:4px 0 10px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;border:1px solid currentColor}
.badge.vulnerable{color:var(--bad)} .badge.safe{color:var(--ok)} .badge.error{color:var(--warn)}
.sev{font-size:12px;opacity:.8;text-transform:uppercase}
</style></head><body>
<h1>PromptShield report</h1>
<div class="meta">Target: ${esc(meta.target)} &middot; ${esc(meta.date)} &middot; judge: ${esc(meta.judge)}</div>
<div class="cards">
  <div class="card"><div class="n ${s.score >= 80 ? 'ok' : 'bad'}">${s.score}%</div>attacks resisted</div>
  <div class="card"><div class="n bad">${s.vulnerable}</div>vulnerable</div>
  <div class="card"><div class="n ok">${s.safe}</div>safe</div>
  <div class="card"><div class="n">${s.bySeverity.critical}</div>critical</div>
  <div class="card"><div class="n">${s.bySeverity.high}</div>high</div>
  <div class="card"><div class="n">${s.errors}</div>errors</div>
</div>
${rows}
</body></html>`;
}

module.exports = { renderHtml, summarize };
