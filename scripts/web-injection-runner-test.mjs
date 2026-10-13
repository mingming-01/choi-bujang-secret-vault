import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = JSON.parse(await readFile(`${root}/xdr/fixtures/web-injection.json`, 'utf8'));
const actual = await runXdr({ root, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
const expected = new Map([
  ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08', 'wi-09', 'wi-15', 'wi-16', 'wi-17']
    .map((id) => [id, 'alert']),
  ...['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
    .map((id) => [id, 'record']),
]);
const basis = new Map([
  ['wi-01', 'URL has an opaque marker; description-only claimed SQL repetitions are not request evidence'],
  ['wi-02', 'URL has an opaque marker; script insertion and count in description are metadata only'],
  ['wi-03', 'URL has an opaque marker; path traversal and count in description are metadata only'],
  ['wi-04', 'URL has an opaque marker; SQL description count is not separate alert evidence'],
  ['wi-05', 'description mentions alternating SQL and script but URL has neither; metadata is ambiguous'],
  ['wi-06', 'command-separator description is a vague candidate, not clear supported request syntax'],
  ['wi-07', 'URL has an opaque marker; path deviation and count in description are metadata only'],
  ['wi-08', 'URL has an opaque marker; database query and count in description are metadata only'],
  ['wi-09', 'single quote metadata without request attack syntax'],
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
assert.deepEqual(actual.counts, { block: 0, alert: 12, record: 14 });
assert.equal(fixture.alerts.filter((alert) => alert.rule.level <= 3).filter((alert) => byId.get(alert.id).action === 'block').length, 0, 'normal events never block');

console.log(`실행기 경보 상관 테스트 통과: ${fixture.alerts.length}개`);
for (const alert of fixture.alerts) console.log(`${alert.id} | ${basis.get(alert.id) ?? 'ordinary input'} | ${byId.get(alert.id).action}`);
console.log(`집계: block ${actual.counts.block} / alert ${actual.counts.alert} / record ${actual.counts.record}`);
