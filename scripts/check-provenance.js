// Pre-flight check: is the ABTalks server ready for a trustworthy PromptShield scan?
// Usage (from the promptshield folder):  npm run check
// It sends ONE interview-start request and reports whether the answer came from live Gemini.
const fs = require('fs');
const path = require('path');

const configPath = path.resolve(process.argv[2] || 'abtalks.config.json');

function done(ok, lines) {
  console.log('');
  for (const l of lines) console.log(l);
  console.log('');
  process.exit(ok ? 0 : 1);
}

async function main() {
  if (!fs.existsSync(configPath)) {
    done(false, [`NOT READY: config not found: ${configPath}`, 'Run this from the promptshield folder.']);
  }

  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const warnings = [];

  if (config.requireProvenance !== true) {
    warnings.push('WARNING: abtalks.config.json is missing  "requireProvenance": true');
    warnings.push('         Without it, mock or fallback answers can be reported as "safe".');
  }
  if (!config.startBodyTemplate) {
    done(false, ['NOT READY: abtalks.config.json has no "startBodyTemplate".']);
  }

  const url = config.startUrl || config.url;
  const sessionId = `check-${Date.now()}`;
  const body = JSON.stringify(config.startBodyTemplate).split('{{sessionId}}').join(sessionId);

  console.log(`Checking ${url} ...`);

  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: config.headers || { 'Content-Type': 'application/json' },
      body,
      signal: AbortSignal.timeout(60000),
    });
  } catch (err) {
    const why = (err.cause && err.cause.code) || err.message;
    done(false, [
      `NOT READY: cannot reach ${url} (${why}).`,
      'Is the ABTalks backend running?  In the server folder run:  npm run dev',
      ...warnings,
    ]);
  }

  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch (_) { /* not JSON */ }

  if (!res.ok) {
    done(false, [
      `NOT READY: server answered HTTP ${res.status}.`,
      `Body: ${text.replace(/\s+/g, ' ').slice(0, 300)}`,
      ...(res.status === 404 ? ['Check "url" in abtalks.config.json (should end with /api/interview).'] : []),
      ...(res.status >= 500 ? ['Check the backend terminal for the error (often a bad GEMINI_API_KEY).'] : []),
      ...warnings,
    ]);
  }

  const header = res.headers.get('x-ai-provenance');
  const bodySource = json && json.provenance && json.provenance.source;
  const source = header || bodySource;
  const reasons = (json && json.provenance && json.provenance.reasons) || [];

  console.log(`HTTP status:        ${res.status}`);
  console.log(`X-AI-Provenance:    ${header || '(none)'}`);
  console.log(`body.provenance:    ${bodySource || '(none)'}${reasons.length ? ' - ' + reasons.join(', ') : ''}`);

  if (!source) {
    done(false, [
      'NOT READY: the server did not report provenance.',
      'Add  EXPOSE_AI_PROVENANCE=true  to server/.env and RESTART the backend (Ctrl+C, then npm run dev).',
      ...warnings,
    ]);
  }
  if (source !== 'live') {
    const fix = {
      mock: 'Set  INTERVIEW_AI_MODE=live  in server/.env and restart the backend.',
      fallback: 'Gemini failed and the app used its mock fallback. Check GEMINI_API_KEY and your quota, wait a minute, retry.',
      none: 'No AI call was made for this request. Check INTERVIEW_AI_MODE and the backend logs.',
    }[source] || 'Unexpected provenance value.';
    done(false, [`NOT READY: provenance is "${source}", not "live".`, fix, ...warnings]);
  }

  done(warnings.length === 0, [
    'READY: the server used live Gemini. You can run the scan.',
    ...warnings,
  ]);
}

main().catch((err) => done(false, [`NOT READY: ${err.stack || err.message}`]));