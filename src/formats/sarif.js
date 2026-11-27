'use strict';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SCORE = { critical: '9.5', high: '8.0', medium: '5.0', low: '2.0' };

// SARIF 2.1.0 so findings appear in GitHub's Security tab (code scanning).
// `artifactUri` should be the config file path, relative to the repo root.
function toSarif(results, { version, artifactUri }) {
  const rules = results.map((r) => ({
    id: r.attack.id,
    name: r.attack.name,
    shortDescription: { text: r.attack.name },
    help: { text: r.attack.fix || 'See PromptShield documentation.' },
    defaultConfiguration: { level: LEVEL[r.attack.severity] || 'warning' },
    properties: { category: r.attack.category, 'security-severity': SCORE[r.attack.severity] || '5.0', tags: ['security', 'llm', r.attack.category] },
  }));

  const findings = results
    .filter((r) => r.verdict === 'vulnerable')
    .map((r) => {
      const t = r.trials || {};
      const rate = t.conclusive ? ` Attack success rate ${t.successes}/${t.conclusive}.` : '';
      return {
        ruleId: r.attack.id,
        level: LEVEL[r.attack.severity] || 'warning',
        message: { text: `${r.attack.name}: ${r.reason}.${rate}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri }, region: { startLine: 1 } } }],
        partialFingerprints: { promptshieldAttack: r.attack.id },
        properties: { attackSuccessRate: t.asr, trials: t.conclusive },
      };
    });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'PromptShield', version, informationUri: 'https://github.com/Aditya-0519/promptshield', rules } },
      results: findings,
    }],
  };
}

module.exports = { toSarif };
