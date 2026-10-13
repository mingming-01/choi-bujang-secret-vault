import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = JSON.parse(await readFile(`${root}/xdr/fixtures/web-injection.json`, 'utf8'));
const actual = await runXdr({ root, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });

// wi-01..wi-08 contain doc-* markers and attack/repetition claims in alert
// descriptions, but no SQL syntax, real script tag, or repeated ../ in URL.
// Their high-severity T1190 metadata warrants review (alert), not block.
const expected = new Map([
  ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08', 'wi-09', 'wi-15', 'wi-16', 'wi-17']
    .map((id) => [id, 'alert']),
  ...['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
    .map((id) => [id, 'record']),
]);
const basis = new Map([
  ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08']
    .map((id) => [id, 'no request-pattern evidence; high-severity T1190 metadata warrants review, not block']),
  ['wi-09', 'ambiguous quote observation in description; no request attack pattern'],
  ['wi-15', 'ambiguous unusual-search observation in description; synthetic marker ignored'],
  ['wi-16', 'ambiguous injection-like observation in description; synthetic marker ignored'],
  ['wi-17', 'ambiguous delimiter observation in description; no specified request pattern'],
  ['wi-10', 'benign course-name use of select'],
  ['wi-11', 'class word script, not an actual tag'],
  ['wi-12', 'benign path word up'],
  ['wi-13', 'request-length observation without an attack pattern'],
  ['wi-14', 'benign SQL course notice title'],
]);

assert.equal(actual.decisions.length, fixture.alerts.length);
const byId = new Map(actual.decisions.map((item) => [item.alertId, item]));
assert.equal(byId.size, fixture.alerts.length);
for (const alert of fixture.alerts) {
  assert.ok(expected.has(alert.id), `missing expectation: ${alert.id}`);
  assert.equal(byId.get(alert.id)?.action, expected.get(alert.id), `${alert.id}: ${basis.get(alert.id) ?? 'ordinary request'}`);
}
assert.equal(expected.size, fixture.alerts.length);

const firstEight = fixture.alerts.filter((alert) => /^wi-0[1-8]$/.test(alert.id));
assert.equal(firstEight.length, 8);
for (const alert of firstEight) {
  const url = decodeURIComponent(alert.data.url.replace(/\+/g, ' '));
  const requestHasSql = /\bunion\s+(?:all\s+)?select\b|\bselect\s+[\w`'"*.,()+%\-\s]{1,100}\s+from\s+[\w`".]+|(?:\bor\b|\band\b)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--(?:\s|$)|\/\*/i.test(url);
  const requestHasScriptTag = /<\s*\/?\s*script\b[^>]*>/i.test(url);
  const requestHasRepeatedTraversal = /(?:\.\.[/\\]){2,}/i.test(url);
  assert.equal(requestHasSql || requestHasScriptTag || requestHasRepeatedTraversal, false, `${alert.id}: doc marker is not request attack evidence`);
  assert.ok(alert.data.url.includes('doc-'), `${alert.id}: expected synthetic marker fixture`);
  assert.ok(alert.rule.level >= 10 && alert.rule.mitre.includes('T1190'), `${alert.id}: review classification comes from alert metadata`);
  assert.equal(byId.get(alert.id)?.action, 'alert', `${alert.id}: metadata may warrant alert, but cannot establish block evidence`);
}
assert.deepEqual(actual.counts, { block: 0, alert: 12, record: 14 });
assert.equal(fixture.alerts.filter((alert) => alert.rule.level <= 3).filter((alert) => byId.get(alert.id).action === 'block').length, 0, 'normal events never block');

console.log(`실행기 분류 기대값 검증: ${fixture.alerts.length}개`);
for (const alert of fixture.alerts) console.log(`${alert.id} | ${basis.get(alert.id) ?? 'ordinary request'} | ${byId.get(alert.id)?.action}`);
console.log(`명세에서 도출한 집계: block ${actual.counts.block} / alert ${actual.counts.alert} / record ${actual.counts.record}`);
