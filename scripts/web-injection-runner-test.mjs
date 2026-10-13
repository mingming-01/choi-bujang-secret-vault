import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = JSON.parse(await readFile(`${root}/xdr/fixtures/web-injection.json`, 'utf8'));
const actual = await runXdr({ root, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
const expected = new Map([
  ['wi-01', 'block'], ['wi-02', 'block'], ['wi-03', 'block'], ['wi-04', 'block'],
  ['wi-05', 'alert'], ['wi-06', 'alert'], ['wi-07', 'block'], ['wi-08', 'block'],
  ['wi-09', 'alert'], ['wi-10', 'record'], ['wi-11', 'record'], ['wi-12', 'record'],
  ['wi-13', 'record'], ['wi-14', 'record'], ['wi-15', 'alert'], ['wi-16', 'alert'],
  ['wi-17', 'alert'], ['wi-18', 'record'], ['wi-19', 'record'], ['wi-20', 'record'],
  ['wi-21', 'record'], ['wi-22', 'record'], ['wi-23', 'record'], ['wi-24', 'record'],
  ['wi-25', 'record'], ['wi-26', 'record'],
]);
const basis = new Map([
  ['wi-01', 'no attack substring in this event URL; only event-local wording about repeats'],
  ['wi-02', 'no attack substring in URL; script count in description is not another fixture event'],
  ['wi-03', 'no traversal substring in URL; event-local description alone does not create peer alerts'],
  ['wi-04', 'no SQL substring in URL; description count is not a count of separate alerts'],
  ['wi-05', 'description explicitly alternates SQL and script evidence, therefore ambiguous'],
  ['wi-06', 'uncertain command-separator signal outside supported clear patterns'],
  ['wi-07', 'no traversal substring in URL; event-local description does not create peer alerts'],
  ['wi-08', 'no SQL substring in URL; event-local description does not create peer alerts'],
  ['wi-09', 'one quote and explicitly no repetition'],
  ['wi-10', 'benign course-name use of select'],
  ['wi-11', 'class word script, not tag insertion'],
  ['wi-12', 'benign path word up'],
  ['wi-13', 'description says no attack string'],
  ['wi-14', 'benign SQL course notice title'],
  ['wi-15', 'one vague unusual-search hint'],
  ['wi-16', 'one uncertain injection-like hint'],
  ['wi-17', 'one delimiter hint'],
]);

assert.equal(actual.decisions.length, fixture.alerts.length);
const byId = new Map(actual.decisions.map((item) => [item.alertId, item]));
assert.equal(byId.size, fixture.alerts.length);
for (const alert of fixture.alerts) {
  assert.ok(expected.has(alert.id), `missing expectation: ${alert.id}`);
  assert.equal(byId.get(alert.id)?.action, expected.get(alert.id), `${alert.id}: ${basis.get(alert.id) ?? 'ordinary input'}`);
}
assert.equal(expected.size, fixture.alerts.length);
assert.deepEqual(actual.counts, { block: 6, alert: 6, record: 14 });
assert.equal(fixture.alerts.filter((alert) => alert.rule.level <= 3).filter((alert) => byId.get(alert.id).action === 'block').length, 0, 'normal events never block');

console.log(`실행기 반복 집계 및 fixture 판정 테스트 통과: ${fixture.alerts.length}개`);
for (const alert of fixture.alerts) console.log(`${alert.id} | ${basis.get(alert.id) ?? 'ordinary input'} | ${byId.get(alert.id).action}`);
console.log(`집계: block ${actual.counts.block} / alert ${actual.counts.alert} / record ${actual.counts.record}`);
