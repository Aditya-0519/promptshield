
const { formatRate } = require('./stats');

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function summarize(results) {
  const vulnerable = results.filter((r) => r.verdict === 'vulnerable');
  const safe = results.filter((r) => r.verdict === 'safe');
  const errors = results.filter((r) => r.verdict === 'error');
  const inconclusive = results.filter((r) => r.verdict === 'inconclusive');

  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const r of vulnerable) {
    bySeverity[r.attack.severity] =
      (bySeverity[r.attack.severity] || 0) + 1;
  }

  const conclusive = safe.length + vulnerable.length;
  const score = conclusive
    ? Math.round((safe.length / conclusive) * 100)
    : null;

  let trialsRun = 0;
  let trialSuccesses = 0;
  let trialConclusive = 0;
  for (const r of results) {
    if (!r.trials) continue;
    trialsRun += r.trials.total;
    trialSuccesses += r.trials.successes;
    trialConclusive += r.trials.conclusive;
  }

  return {
    total: results.length,
    trialsRun,
    overallAsr: trialConclusive ? trialSuccesses / trialConclusive : null,
    vulnerable: vulnerable.length,
    safe: safe.length,
    inconclusive: inconclusive.length,
    errors: errors.length,
    bySeverity,
    score,
  };
}

function renderTrials(trials) {
  if (!trials || trials.total < 2) return '';
  const rows = trials.runs.map((t) => `<li>Trial ${esc(t.trial)}: <b>${esc(String(t.verdict).toUpperCase())}</b>` +
    `${t.firstLeakStep ? ` (first leak at step ${esc(t.firstLeakStep)})` : ''}` +
    `${t.cause ? ` - ${esc(t.cause)}` : ''}</li>`).join('');
  return `<section class="evidence"><h3>Trials</h3>
    <p><b>Attack success rate:</b> ${esc(formatRate(trials.successes, trials.conclusive))}</p>
    <p>${esc(trials.safe)} safe, ${esc(trials.successes)} leaked, ${esc(trials.inconclusive)} inconclusive, ${esc(trials.errors)} errors</p>
    <ul>${rows}</ul></section>`;
}

function renderEvidence(evidence) {
  if (!evidence) return '';

  const stageRows = (evidence.stageEvidence || []).map((stage) => `
    <li>
      <b>Step ${esc(stage.step)} — ${esc(stage.label)}:</b>
      ${stage.passed ? 'expected marker observed' : 'expected marker NOT observed'}
      ${stage.observedMarkers?.length
        ? ` — ${esc(stage.observedMarkers.join(', '))}`
        : ''}
    </li>
  `).join('');

  const secrets = (evidence.matchedSecrets || []).map(esc);
  const markers = (evidence.matchedMarkers || []).map(esc);
  const first = evidence.firstLeakStep
    ? `Step ${esc(evidence.firstLeakStep)}`
    : 'No assistant step';
  const stagesPassed = (evidence.stageEvidence || []).filter((s) => s.passed).length;

  return `
    <section class="evidence">
      <h3>Detection evidence</h3>
      <p><b>Evidence source:</b> ${esc(evidence.source || 'response')}</p>
      <p><b>First detected leak:</b> ${first}</p>
      <p><b>Extraction assessment:</b> ${esc(evidence.extractionAssessment || 'not assessed')}</p>
      <p><b>Unique protected secrets disclosed:</b> ${secrets.length}${secrets.length ? ' — ' + secrets.join(', ') : ''}</p>
      ${evidence.systemPromptLeak ? `<p><b>System prompt reproduced:</b> ~${Math.round(evidence.systemPromptLeak.coverage * 100)}% at step ${esc(evidence.systemPromptLeak.step)}</p>` : ''}
      ${(evidence.suppressed || []).length ? `<p><b>Ignored (inside a refusal):</b> ${evidence.suppressed.map((x) => esc(x.value)).join(', ')}</p>` : ''}
      <p><b>Matched attack markers:</b> ${markers.length ? markers.join(', ') : 'None'}</p>
      ${evidence.completeSet?.expected?.length
        ? `<p><b>Complete marker set:</b> ${evidence.completeSet.observed.length}/${evidence.completeSet.expected.length} observed</p>`
        : ''}
      ${stageRows ? `<p><b>Expected stage sequence</b> (${stagesPassed}/${evidence.stageEvidence.length} stage markers observed)</p><ul>${stageRows}</ul>
        <p><b>Stage sequence complete:</b> ${evidence.stageSequenceComplete ? 'Yes' : 'No'}</p>` : ''}
    </section>
  `;
}

function renderStepSecrets(item) {
  if (!item) return '';
  const lines = [];
  if (item.newSecrets?.length) {
    lines.push(`<b>New secrets disclosed:</b> ${item.newSecrets.map(esc).join(', ')}`);
  }
  if (item.repeatedSecrets?.length) {
    lines.push(`<b>Repeated (already disclosed earlier):</b> ${item.repeatedSecrets.map(esc).join(', ')}`);
  }
  return lines.map((l) => `<p class="step-meta">${l}</p>`).join('');
}

function renderSteps(steps, evidence) {
  if (!Array.isArray(steps) || !steps.length) return '';

  return `
    <p><b>Conversation steps:</b></p>
    ${steps.map((step, index) => {
      const item = (evidence?.stepEvidence || []).find((e) => e.step === index + 1);
      return `
      <div class="step">
        <p><b>Step ${index + 1} - User:</b></p>
        <pre>${esc(step.prompt)}</pre>
        <p><b>Step ${index + 1} - Assistant:</b></p>
        <pre>${esc(step.text)}</pre>
        ${item && item.hasFinding
          ? `<p class="step-meta bad">Finding detected in this assistant response</p>`
          : ''}
        ${renderStepSecrets(item)}
        <p class="step-meta">HTTP ${esc(step.status)} · ${esc(step.ms)} ms</p>
      </div>
    `;
    }).join('\n')}
  `;
}

function renderHtml(results, meta) {
  const s = summarize(results);

  const sorted = [...results].sort((a, b) => {
    const av = a.verdict === 'vulnerable' ? 0 : 1;
    const bv = b.verdict === 'vulnerable' ? 0 : 1;

    if (av !== bv) return av - bv;

    return (
      (SEV_ORDER[a.attack.severity] ?? 9) -
      (SEV_ORDER[b.attack.severity] ?? 9)
    );
  });

  const rows = sorted.map((r) => {
    const cls = r.verdict;
    const hasSteps =
      Array.isArray(r.response.steps) && r.response.steps.length > 1;

    const attackPrompt = Array.isArray(r.attack.steps)
      ? r.attack.steps.join('\n\n')
      : r.attack.prompt;

    return `
    <details class="finding ${esc(cls)}">
      <summary>
        <span class="badge ${esc(cls)}">${esc(r.verdict.toUpperCase())}</span>
        <span class="sev ${esc(r.attack.severity)}">${esc(r.attack.severity)}</span>
        <strong>${esc(r.attack.id)}</strong> ${esc(r.attack.name)}
        ${r.trials && r.trials.total > 1 ? `<span class="sev">${esc(r.trials.successes)}/${esc(r.trials.conclusive)} leaked</span>` : ''}
      </summary>
      <div class="body">
        <p><b>Category:</b> ${esc(r.attack.category)}</p>
        <p><b>Why:</b> ${esc(r.reason)}</p>
        <p><b>Attack prompt:</b></p>
        <pre>${esc(attackPrompt)}</pre>
        ${renderTrials(r.trials)}
        ${renderEvidence(r.evidence)}
        ${hasSteps ? renderSteps(r.response.steps, r.evidence) : ''}
        <p><b>Complete target transcript:</b></p>
        <pre>${esc(r.response.text || r.response.error || '(empty)')}</pre>
        ${r.verdict === 'vulnerable'
          ? `<p><b>How to fix:</b> ${esc(r.attack.fix)}</p>`
          : ''}
      </div>
    </details>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PromptShield report</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--card:#f6f6f7;--line:#dcdce0;--bad:#c0392b;--ok:#1e8449;--warn:#b9770e}
@media(prefers-color-scheme:dark){:root{--bg:#161618;--fg:#ececec;--card:#222226;--line:#38383d;--bad:#ff6b5b;--ok:#4cc67f;--warn:#f0b04a}}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:900px;margin-inline:auto}
h1{margin:0 0 4px}
.meta{opacity:.7;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card .n{font-size:28px;font-weight:700}
.bad{color:var(--bad)}
.ok{color:var(--ok)}
.finding{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--card)}
.finding summary{padding:10px 12px;cursor:pointer;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.body{padding:0 14px 12px}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;margin:4px 0 10px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;border:1px solid currentColor}
.badge.vulnerable{color:var(--bad)}
.badge.safe{color:var(--ok)}
.badge.error,.badge.inconclusive{color:var(--warn)}
.sev{font-size:12px;opacity:.8;text-transform:uppercase}
.step{border-left:3px solid var(--line);padding-left:12px;margin:14px 0}
.step-meta{font-size:12px;opacity:.65}.bad{color:var(--bad)}.evidence{border:1px solid var(--line);border-radius:8px;padding:10px;margin:12px 0;background:var(--bg)}.evidence h3{margin:0 0 8px;font-size:16px}.evidence ul{padding-left:22px}
</style>
</head>
<body>
<h1>PromptShield report</h1>
<div class="meta">
Target: ${esc(meta.target)}
&middot; ${esc(meta.date)}
&middot; judge: ${esc(meta.judge)}
&middot; transport: ${esc(meta.transport)}
${meta.model ? `&middot; model: ${esc(meta.model)}` : ''}
&middot; trials per attack: ${esc(meta.trials || 1)}
${meta.redacted === false ? '&middot; <b class="bad">UNREDACTED: contains full secrets, do not share</b>' : '&middot; secrets redacted'}
${meta.toolVersion ? `&middot; PromptShield ${esc(meta.toolVersion)}` : ''}
</div>
<div class="cards">
  <div class="card"><div class="n ${s.score !== null && s.score >= 80 ? 'ok' : 'bad'}">${s.score === null ? 'n/a' : s.score + '%'}</div>conclusive attacks resisted</div>
  <div class="card"><div class="n ${s.overallAsr ? 'bad' : 'ok'}">${s.overallAsr === null ? 'n/a' : Math.round(s.overallAsr * 100) + '%'}</div>attack success rate (${esc(s.trialsRun)} trials)</div>
  <div class="card"><div class="n bad">${s.vulnerable}</div>vulnerable</div>
  <div class="card"><div class="n ok">${s.safe}</div>safe</div>
  <div class="card"><div class="n">${s.bySeverity.critical}</div>critical</div>
  <div class="card"><div class="n">${s.bySeverity.high}</div>high</div>
  <div class="card"><div class="n">${s.inconclusive}</div>inconclusive</div>
  <div class="card"><div class="n">${s.errors}</div>errors</div>
</div>
${rows}
</body>
</html>`;
}

module.exports = { renderHtml, summarize };
