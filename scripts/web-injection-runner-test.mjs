import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = JSON.parse(await readFile(`${root}/xdr/fixtures/web-injection.json`, 'utf8'));
const temporaryRoot = await mkdtemp(join(tmpdir(), 'web-injection-runner-'));

try {
  const fixtureDir = join(temporaryRoot, 'xdr', 'fixtures');
  const moduleDir = join(temporaryRoot, 'xdr', 'web-injection');
  await mkdir(fixtureDir, { recursive: true });
  await mkdir(moduleDir, { recursive: true });
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
  await writeFile(join(moduleDir, 'decide.mjs'), await readFile(`${root}/xdr/web-injection/decide.mjs`, 'utf8'), 'utf8');
  await writeFile(join(moduleDir, 'respond.mjs'), await readFile(`${root}/xdr/web-injection/respond.mjs`, 'utf8'), 'utf8');

  const actual = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const expected = new Map([
    ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08']
      .map((id) => [id, 'alert']),
    ...['wi-09', 'wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-15', 'wi-16', 'wi-17', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
      .map((id) => [id, 'record']),
  ]);
  const basis = new Map([
    ['wi-01', 'high level + T1190 is review-only; description count and doc marker are not attack evidence'],
    ['wi-02', 'high level + T1190 is review-only; script and count claims are metadata only'],
    ['wi-03', 'high level + T1190 is review-only; URL has no traversal pattern'],
    ['wi-04', 'high level + T1190 is review-only; description count is not separate alert evidence'],
    ['wi-05', 'high level + T1190 is review-only; description-only overlapping claims are not request evidence'],
    ['wi-06', 'high level + T1190 is review-only; command-separator description is not supported request syntax'],
    ['wi-07', 'high level + T1190 is review-only; URL has no traversal pattern'],
    ['wi-08', 'high level + T1190 is review-only; database query claim is not request evidence'],
    ['wi-09', 'description-only quote claim, absent from URL'],
    ['wi-10', 'benign course-name use of select'],
    ['wi-11', 'class word script, not an actual tag'],
    ['wi-12', 'benign path word up'],
    ['wi-13', 'no request attack signal; severity is below review threshold'],
    ['wi-14', 'benign SQL course notice title'],
    ['wi-15', 'description-only vague hint'],
    ['wi-16', 'description-only injection-like hint'],
    ['wi-17', 'description-only delimiter hint'],
  ]);

  assert.equal(actual.decisions.length, fixture.alerts.length);
  const byId = new Map(actual.decisions.map((item) => [item.alertId, item]));
  assert.equal(byId.size, fixture.alerts.length);
  for (const alert of fixture.alerts) {
    assert.ok(expected.has(alert.id), `missing expectation: ${alert.id}`);
    assert.equal(byId.get(alert.id)?.action, expected.get(alert.id), `${alert.id}: ${basis.get(alert.id) ?? 'ordinary input'}`);
  }
  assert.equal(expected.size, fixture.alerts.length);
  assert.deepEqual(actual.counts, { block: 0, alert: 8, record: 18 });
  assert.equal(fixture.alerts.filter((alert) => alert.rule.level <= 3).filter((alert) => byId.get(alert.id).action !== 'record').length, 0, 'normal events remain record');

  console.log(`실행기 경보 판정 테스트 계약 확인: ${fixture.alerts.length}개`);
  for (const alert of fixture.alerts) console.log(`${alert.id} | ${basis.get(alert.id) ?? 'ordinary input'} | ${byId.get(alert.id).action}`);
  console.log(`집계 기대값: block ${actual.counts.block} / alert ${actual.counts.alert} / record ${actual.counts.record}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
