import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const temporaryRoot = await mkdtemp(join(tmpdir(), 'web-injection-repeat-'));
try {
  const moduleDir = join(temporaryRoot, 'xdr', 'web-injection');
  const fixtureDir = join(temporaryRoot, 'xdr', 'fixtures');
  await mkdir(moduleDir, { recursive: true });
  await mkdir(fixtureDir, { recursive: true });
  await writeFile(join(moduleDir, 'decide.mjs'), await readFile(join(projectRoot, 'xdr', 'web-injection', 'decide.mjs'), 'utf8'), 'utf8');
  await writeFile(join(moduleDir, 'respond.mjs'), await readFile(join(projectRoot, 'xdr', 'web-injection', 'respond.mjs'), 'utf8'), 'utf8');

  const fixture = {
    schema: 'aleph.xdr.fixture.v1',
    moduleKey: 'web-injection',
    alerts: [
      { id: 'same-a', data: { srcip: '203.0.113.200', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'same-b', data: { srcip: '203.0.113.200', url: '/search?q=union+select+email+from+accounts', count: '1' } },
      { id: 'different-pattern', data: { srcip: '203.0.113.200', url: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', count: '1' } },
      { id: 'different-source', data: { srcip: '198.51.100.200', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'marker-count', data: { srcip: '192.0.2.200', url: '/search?q=doc-sql-chain', count: '3' } },
      { id: 'description-only', rule: { description: '같은 주소에서 SQL 구문이 50번 반복됐습니다.' }, data: { srcip: '192.0.2.202', url: '/search?q=select-course', count: '1' } },
      { id: 'description-attack-words-only', rule: { description: '스크립트 삽입 공격 표기가 30번 반복됐습니다.' }, data: { srcip: '192.0.2.204', url: '/search?q=select-course', count: '1' } },
      { id: 'count-only', data: { srcip: '192.0.2.203', url: '/search?q=select-course', count: '90' } },
      { id: 'normal', data: { srcip: '192.0.2.201', url: '/search?q=select-course', count: '1' } },
    ],
  };
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

  const result = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const actualById = new Map(result.decisions.map((decision) => [decision.alertId, decision]));
  assert.equal(actualById.get('same-a')?.action, 'block', 'separate same-source SQL alerts correlate');
  assert.equal(actualById.get('same-b')?.action, 'block', 'same-source SQL peer is also blockable');
  assert.equal(actualById.get('different-pattern')?.action, 'alert', 'different patterns do not share evidence');
  assert.equal(actualById.get('different-source')?.action, 'alert', 'different sources do not share evidence');
  assert.equal(actualById.get('marker-count')?.action, 'record', 'doc marker and data.count are not attack or repetition evidence');
  assert.equal(actualById.get('description-only')?.action, 'record', 'description-only repetition is not an attack signal');
  assert.equal(actualById.get('description-attack-words-only')?.action, 'record', 'attack words and repetition claims in a description are not request signals');
  assert.equal(actualById.get('count-only')?.action, 'record', 'count-only is not an attack signal');
  assert.equal(actualById.get('normal')?.action, 'record', 'normal event remains record');
  assert.deepEqual(result.counts, { block: 2, alert: 2, record: 5 });

  console.log('실행기 반복 집계 확인: 동일 출발지·패턴의 별도 경보만 차단 근거이며 marker/설명/count는 공격 신호가 아님');
  for (const decision of result.decisions) console.log(`${decision.alertId} | ${decision.action}`);
  console.log(`집계: block ${result.counts.block} / alert ${result.counts.alert} / record ${result.counts.record}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
