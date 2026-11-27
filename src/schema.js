'use strict';

// Validation for attack files and target config. Fail loudly: a typo in
// "detect" must never silently turn into a false SAFE.

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const DETECT_KEYS = ['contains_any', 'regex', 'complete_set'];
const ATTACK_KEYS = [
  'id', 'name', 'category', 'severity', 'prompt', 'steps', 'detect', 'fix',
  'step_expectations', 'description', 'owasp', 'tags',
];

const isStr = (v) => typeof v === 'string' && v.trim().length > 0;
const isStrArray = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');

// Rejects the classic catastrophic-backtracking shapes: a quantified group that
// itself contains a quantifier, e.g. (a+)+ or (.*)* .
function riskyRegex(source) {
  return /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/.test(source);
}

function validateAttack(attack, where) {
  const errors = [];
  const at = (field, msg) => errors.push(`${where}${attack && attack.id ? ` (${attack.id})` : ''}: "${field}" ${msg}`);

  if (!attack || typeof attack !== 'object' || Array.isArray(attack)) {
    return [`${where}: attack must be an object`];
  }
  for (const key of Object.keys(attack)) {
    if (!ATTACK_KEYS.includes(key)) at(key, `is not a known attack field (known: ${ATTACK_KEYS.join(', ')})`);
  }
  if (!isStr(attack.id)) at('id', 'is required (string)');
  if (!isStr(attack.name)) at('name', 'is required (string)');
  if (!isStr(attack.category)) at('category', 'is required (string)');
  if (!SEVERITIES.includes(attack.severity)) at('severity', `must be one of ${SEVERITIES.join(', ')}`);

  const hasPrompt = isStr(attack.prompt);
  const hasSteps = Array.isArray(attack.steps) && attack.steps.length > 0;
  if (!hasPrompt && !hasSteps) at('prompt', 'or "steps" is required');
  if (hasPrompt && hasSteps) at('prompt', 'and "steps" cannot both be set');
  if (attack.steps !== undefined && !(hasSteps && attack.steps.every(isStr))) {
    at('steps', 'must be a non-empty array of non-empty strings');
  }

  if (attack.detect !== undefined) {
    const d = attack.detect;
    if (!d || typeof d !== 'object' || Array.isArray(d)) {
      at('detect', 'must be an object');
    } else {
      for (const key of Object.keys(d)) {
        if (!DETECT_KEYS.includes(key)) {
          at(`detect.${key}`, `is not a known detector (known: ${DETECT_KEYS.join(', ')})`);
        } else if (!isStrArray(d[key])) {
          at(`detect.${key}`, 'must be an array of strings');
        }
      }
      for (const pattern of Array.isArray(d.regex) ? d.regex : []) {
        const source = String(pattern).startsWith('(?i)') ? String(pattern).slice(4) : String(pattern);
        try {
          new RegExp(source, 'i'); // eslint-disable-line no-new
        } catch (err) {
          at('detect.regex', `has an invalid pattern ${JSON.stringify(pattern)}: ${err.message}`);
          continue;
        }
        if (riskyRegex(source)) {
          at('detect.regex', `pattern ${JSON.stringify(pattern)} can backtrack catastrophically; simplify it`);
        }
      }
    }
  }

  if (attack.step_expectations !== undefined) {
    const se = attack.step_expectations;
    if (!Array.isArray(se)) {
      at('step_expectations', 'must be an array');
    } else {
      const count = hasSteps ? attack.steps.length : 1;
      if (se.length > count) at('step_expectations', `has ${se.length} entries but the attack has only ${count} step(s)`);
      se.forEach((e, i) => {
        if (!e || !isStrArray(e.expect_any) || !e.expect_any.length) {
          at(`step_expectations[${i}].expect_any`, 'must be a non-empty array of strings');
        }
      });
    }
  }
  return errors;
}

function validateAttacks(list, where) {
  const errors = [];
  const seen = new Set();
  list.forEach((attack, i) => {
    errors.push(...validateAttack(attack, `${where}[${i}]`));
    if (attack && attack.id) {
      if (seen.has(attack.id)) errors.push(`${where}[${i}]: duplicate attack id "${attack.id}"`);
      seen.add(attack.id);
    }
  });
  return errors;
}

module.exports = { validateAttack, validateAttacks, riskyRegex, SEVERITIES };
