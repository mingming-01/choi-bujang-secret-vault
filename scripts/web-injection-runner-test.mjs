import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = JSON.parse(await readFile(`${root}/xdr/fixtures/web-injection.json`, 'utf8'));
const patterns = await readFile(`${root}/xdr/web-injection/patterns.json`, 'utf8');
const temporaryRoot = await mkdtemp(join(tmpdir(), 'web-injection-runner-'));

try {
  const fixtureDir = join(temporaryRoot, 'xdr', 'fixtures');
  const moduleDir = join(temporaryRoot, 'xdr', 'web-injection');
  await mkdir(fixtureDir, { recursive: true });
  await mkdir(moduleDir, { recursive: true });
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
  await writeFile(join(moduleDir, 'decide.mjs'), await readFile(`${root}/xdr/web-injection/decide.mjs`, 'utf8'), 'utf8');
  await writeFile(join(moduleDir, 'respond.mjs'), await readFile(`${root}/xdr/web-injection/respond.mjs`, 'utf8'), 'utf8');
  await writeFile(join(moduleDir, 'patterns.json'), patterns, 'utf8');

  const actual = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const expected = new Map([
    ['wi-01', 'block'], ['wi-02', 'alert'], ['wi-03', 'block'], ['wi-04', 'block'],
    ['wi-05', 'alert'], ['wi-06', 'alert'], ['wi-07', 'block'], ['wi-08', 'alert'],
    ['wi-09', 'alert'], ['wi-10', 'record'], ['wi-11', 'record'], ['wi-12', 'alert'],
    ['wi-13', 'record'], ['wi-14', 'record'], ['wi-15', 'alert'], ['wi-16', 'alert'],
    ['wi-17', 'alert'],
    ...['wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
      .map((id) => [id, 'record']),
  ]);
  const basis = new Map([
    ['wi-01', 'clear SQL injection and independent wi-04 repeat from the same source'],
    ['wi-02', 'actual script tag; only one event, so alert'],
    ['wi-03', 'repeated traversal and independent wi-07 repeat from the same source'],
    ['wi-04', 'clear SQL injection and independent wi-01 repeat from the same source'],
    ['wi-05', 'SQL and script patterns overlap; ambiguous, never block'],
    ['wi-06', 'suspicious command separator and command token in request'],
    ['wi-07', 'repeated traversal and independent wi-03 repeat from the same source'],
    ['wi-08', 'clear but single SQL pattern, so alert'],
    ['wi-09', 'isolated quote in actual request, so alert'],
    ['wi-10', 'ordinary select word in a course name'],
    ['wi-11', 'ordinary script word without an HTML tag; record'],
    ['wi-12', 'single traversal segment; review only'],
    ['wi-13', 'ordinary request; metadata does not escalate it'],
    ['wi-14', 'ordinary SQL course title; no injection syntax'],
    ['wi-15', 'partial UNION request signal'],
    ['wi-16', 'incomplete script tag in request'],
    ['wi-17', 'suspicious command separator in request'],
  ]);

  assert.equal(actual.decisions.length, fixture.alerts.length);
  const byId = new Map(actual.decisions.map((item) => [item.alertId, item]));
  assert.equal(byId.size, fixture.alerts.length);
  for (const alert of fixture.alerts) {
    assert.ok(expected.has(alert.id), `missing expectation: ${alert.id}`);
    assert.equal(byId.get(alert.id)?.action, expected.get(alert.id), `${alert.id}: ${basis.get(alert.id) ?? 'ordinary input'}`);
  }
  assert.equal(expected.size, fixture.alerts.length);
  assert.deepEqual(actual.counts, { block: 4, alert: 9, record: 13 });
  assert.equal(actual.response?.appliedToZtna, false, 'candidate rules are not applied to ZTNA');
  assert.equal(actual.response?.candidateRules.length, 4, 'only repeated actual attacks become expiring candidate rules');
  assert.equal(actual.response?.blockedCandidates, 4);
  assert.equal(fixture.alerts.filter((alert) => alert.id >= 'wi-18' && byId.get(alert.id).action !== 'record').length, 0, 'normal events remain record');

  console.log(`실행기 경보 판정 테스트 계약: ${fixture.alerts.length}개 fixture`);
  for (const alert of fixture.alerts) console.log(`${alert.id} | ${basis.get(alert.id) ?? 'ordinary input'} | ${byId.get(alert.id).action}`);
  console.log(`집계 기대값: block ${actual.counts.block} / alert ${actual.counts.alert} / record ${actual.counts.record}`);
  console.log(`응답 후보: ${actual.response?.blockedCandidates ?? 0}, ZTNA 적용=${actual.response?.appliedToZtna}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
