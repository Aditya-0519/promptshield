const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateAttack, riskyRegex } = require('../src/schema');
const { loadAttacks } = require('../src/scanner');

const good = { id: 'X-1', name: 'n', category: 'c', severity: 'high', prompt: 'p', detect: { contains_any: ['A'] }, fix: 'f' };

test('a valid attack passes', () => assert.deepEqual(validateAttack(good, 'f.json'), []));

test('a typo in detect is named, with file and attack id', () => {
  const errs = validateAttack({ ...good, detect: { contain_any: ['A'] } }, 'bad.json[0]');
  assert.match(errs[0], /bad\.json\[0\] \(X-1\): "detect\.contain_any" is not a known detector/);
});

test('missing prompt/steps, bad severity, bad regex, risky regex', () => {
  const e1 = validateAttack({ ...good, prompt: undefined }, 'f');
  assert.match(e1.join(), /prompt/);
  assert.match(validateAttack({ ...good, severity: 'urgent' }, 'f').join(), /severity/);
  assert.match(validateAttack({ ...good, detect: { regex: ['('] } }, 'f').join(), /invalid pattern/);
  assert.match(validateAttack({ ...good, detect: { regex: ['(a+)+$'] } }, 'f').join(), /backtrack/);
  assert.ok(riskyRegex('(.*)*'));
  assert.ok(!riskyRegex('[A-Z]{3}-\\d+'));
});

test('loadAttacks throws listing every problem across files', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-'));
  fs.writeFileSync(path.join(dir, 'a.json'), JSON.stringify([good, { ...good, detect: { containsAny: ['x'] } }]));
  fs.writeFileSync(path.join(dir, 'b.json'), '{not json');
  assert.throws(() => loadAttacks(dir), (err) => /a\.json\[1\]/.test(err.message) && /duplicate attack id/.test(err.message) && /b\.json: not valid JSON/.test(err.message));
});

test('every bundled attack file is valid', () => {
  const attacks = loadAttacks(path.join(__dirname, '..', 'attacks'));
  assert.ok(attacks.length >= 27);
  assert.ok(attacks.some((a) => Array.isArray(a.steps) && a.steps.length > 1));
  const basileak = loadAttacks(path.join(__dirname, '..', 'attacks', 'basileak'));
  assert.equal(basileak.length, 1);
});
