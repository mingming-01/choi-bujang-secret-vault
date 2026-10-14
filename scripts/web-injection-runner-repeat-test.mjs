import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { respond } from '../xdr/web-injection/respond.mjs';
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
  await writeFile(join(moduleDir, 'patterns.json'), await readFile(join(projectRoot, 'xdr', 'web-injection', 'patterns.json'), 'utf8'), 'utf8');

  const fixture = {
    schema: 'aleph.xdr.fixture.v1',
    moduleKey: 'web-injection',
    alerts: [
      { id: 'same-a', data: { srcip: '203.0.113.200', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'same-b', data: { srcip: '203.0.113.200', url: '/search?q=union+select+email+from+accounts', count: '1' } },
      { id: 'different-pattern', data: { srcip: '203.0.113.200', url: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', count: '1' } },
      { id: 'different-source', data: { srcip: '198.51.100.200', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'duplicate-id', data: { srcip: '203.0.113.201', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'duplicate-id', data: { srcip: '203.0.113.201', url: '/search?q=union+select+email+from+accounts', count: '1' } },
      { id: 'invalid-ip-a', data: { srcip: '999.1.1.1', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'invalid-ip-b', data: { srcip: '999.1.1.1', url: '/search?q=union+select+email+from+accounts', count: '1' } },
      { id: 'ipv6-mapped-a', data: { srcip: '::ffff:203.0.113.202', url: '/search?q=union+select+name+from+users', count: '1' } },
      { id: 'ipv6-mapped-b', data: { srcip: '::ffff:203.0.113.202', url: '/search?q=union+select+email+from+accounts', count: '1' } },
      { id: 'marker-count', data: { srcip: '192.0.2.200', url: '/search?q=doc-sql-chain', count: '3' } },
      { id: 'description-only', rule: { description: '같은 주소에서 SQL 구문이 50번 반복됐습니다.' }, data: { srcip: '192.0.2.202', url: '/search?q=select-course', count: '1' } },
      { id: 'description-attack-words-only', rule: { description: '스크립트 삽입 공격 표기가 30번 반복됐습니다.' }, data: { srcip: '192.0.2.204', url: '/search?q=select-course', count: '1' } },
      { id: 'count-only', data: { srcip: '192.0.2.203', url: '/search?q=select-course', count: '90' } },
      { id: 'normal', data: { srcip: '192.0.2.201', url: '/search?q=select-course', count: '1' } },
      { id: 'high-risk-metadata-only', rule: { level: 10, mitre: ['T1190'] }, data: { srcip: '192.0.2.205', url: '/search?q=select-course', count: '1' } },
    ],
  };
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

  const result = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const actualById = new Map(result.decisions.map((decision) => [decision.alertId, decision]));
  assert.equal(actualById.get('same-a')?.action, 'block', 'separate same-source SQL alerts correlate');
  assert.equal(actualById.get('same-b')?.action, 'block', 'same-source SQL peer is also blockable');
  assert.equal(actualById.get('different-pattern')?.action, 'alert', 'different patterns do not share evidence');
  assert.equal(actualById.get('different-source')?.action, 'alert', 'different sources do not share evidence');
  assert.equal(result.decisions.filter((decision) => decision.alertId === 'duplicate-id').every((decision) => decision.action === 'alert'), true, 'duplicate IDs cannot establish distinct events');
  assert.equal(actualById.get('invalid-ip-a')?.action, 'alert', 'invalid source IPs cannot correlate');
  assert.equal(actualById.get('invalid-ip-b')?.action, 'alert', 'invalid source IPs cannot correlate');
  assert.equal(actualById.get('ipv6-mapped-a')?.action, 'block', 'runner and decider normalize IPv4-embedded IPv6 identically');
  assert.equal(actualById.get('ipv6-mapped-b')?.action, 'block', 'IPv4-embedded IPv6 peer shares canonical source');
  assert.equal(actualById.get('marker-count')?.action, 'record', 'doc marker and data.count are not attack or repetition evidence');
  assert.equal(actualById.get('description-only')?.action, 'record', 'description-only repetition is not an attack signal');
  assert.equal(actualById.get('description-attack-words-only')?.action, 'record', 'attack words and repetition claims in a description are not request signals');
  assert.equal(actualById.get('count-only')?.action, 'record', 'count-only is not an attack signal');
  assert.equal(actualById.get('normal')?.action, 'record', 'normal event remains record');
  assert.equal(actualById.get('high-risk-metadata-only')?.action, 'alert', 'high-risk metadata requests review but cannot block');
  assert.deepEqual(result.counts, { block: 4, alert: 7, record: 5 });
  assert.equal(result.response?.candidateRules.length, 0, 'missing timestamps prevent response candidates without changing decisions');
  assert.equal(result.response?.appliedToZtna, false, 'candidate rules are not applied to ZTNA');

  const responderRoot = join(temporaryRoot, 'responder-check');
  await mkdir(join(responderRoot, 'xdr'), { recursive: true });
  const responderResult = await respond({
    root: responderRoot,
    decisions: [
      { alertId: 'source-address-fallback', action: 'block' },
      { alertId: 'source-fallback', action: 'block' },
      { alertId: 'invalid-source', action: 'block' },
    ],
    alerts: [
      {
        id: 'source-address-fallback',
        timestamp: '2026-09-27T09:00:00Z',
        sourceAddress: '203.0.113.210',
        data: { srcip: 'not-an-ip' },
      },
      {
        id: 'source-fallback',
        timestamp: '2026-09-27T09:00:00Z',
        source: '2001:db8::1',
      },
      {
        id: 'invalid-source',
        timestamp: '2026-09-27T09:00:00Z',
        data: { srcip: '999.1.1.1' },
      },
    ],
  });
  assert.deepEqual(responderResult.rules.map((rule) => rule.source), [
    '203.0.113.210',
    '2001:0db8:0000:0000:0000:0000:0000:0001',
  ], 'responder follows the decider/runner source fallback and canonical IP validation');
  assert.equal(responderResult.blocked, 2);
  const responderLog = await readFile(join(responderRoot, 'xdr', 'alerts.log'), 'utf8');
  assert.match(responderLog, /alert=invalid-source action=block_skipped_invalid_source/);

  console.log('실행기 반복 집계 확인: 동일 출처·패턴의 고유 경보 ID만 차단 근거이며 marker/설명/count는 공격 신호가 아님');
  for (const decision of result.decisions) console.log(`${decision.alertId} | ${decision.action}`);
  console.log(`집계: block ${result.counts.block} / alert ${result.counts.alert} / record ${result.counts.record}`);
  console.log('응답기 확인: 유효한 대체 출처 필드에서 후보 생성, 잘못된 IP 출처는 거부');
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
