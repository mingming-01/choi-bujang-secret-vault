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
      { id: 'overlapping-patterns', data: { srcip: '203.0.113.200', url: '/search?q=union+select+name+from+users+%3Cscript%3Ealert(1)%3C%2Fscript%3E', count: '1' } },
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
      { id: 'ambiguous-partial-sql', data: { srcip: '192.0.2.206', url: '/search?q=UNION%20' } },
      { id: 'ambiguous-bare-script', data: { srcip: '192.0.2.207', url: '/search?q=%3Cscript' } },
      { id: 'ambiguous-single-traversal', data: { srcip: '192.0.2.208', url: '/files?path=../notes' } },
      { id: 'ambiguous-command-separator', data: { srcip: '192.0.2.209', url: '/search?q=hello%3Bwhoami' } },
      { id: 'ambiguous-isolated-quote', data: { srcip: '192.0.2.210', url: '/search?q=%27' } },
    ],
  };
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

  const result = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const actualById = new Map(result.decisions.map((decision) => [decision.alertId, decision]));
  assert.equal(actualById.get('same-a')?.action, 'block', 'separate same-source SQL alerts correlate');
  assert.equal(actualById.get('same-b')?.action, 'block', 'same-source SQL peer is also blockable');
  assert.equal(actualById.get('different-pattern')?.action, 'block', 'same-source alerts with different clear patterns share repetition evidence');
  assert.equal(actualById.get('overlapping-patterns')?.action, 'alert', 'an alert matching multiple clear patterns is excluded from repetition groups');
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
  assert.equal(actualById.get('high-risk-metadata-only')?.action, 'record', 'metadata alone does not create a request signal');
  for (const id of [
    'ambiguous-partial-sql', 'ambiguous-bare-script'
  ]) {
    assert.equal(actualById.get(id)?.action, 'alert', `${id} is a request-level ambiguous signal`);
  }

  for (const id of ['ambiguous-single-traversal', 'ambiguous-command-separator', 'ambiguous-isolated-quote']) {
    assert.equal(actualById.get(id)?.action, 'record', `${id} alone is insufficient evidence`);
  }
  assert.deepEqual(result.counts, { block: 5, alert: 8, record: 9 });
  assert.equal(result.response?.candidateRules.length, 0, 'missing timestamps prevent response candidates without changing decisions');
  assert.equal(result.response?.appliedToZtna, false, 'candidate rules are not applied to ZTNA when no valid response candidates exist');
  const responderRoot = join(temporaryRoot, 'responder-check');
  await mkdir(join(responderRoot, 'xdr'), { recursive: true });
  const responderResult = await respond({
    root: responderRoot,
    decisions: [
      {
        alertId: 'source-address-fallback',
        action: 'block',
        reason: 'sql-injection: test evidence',
      },
      {
        alertId: 'source-fallback',
        action: 'block',
        reason: 'sql-injection: test evidence',
      },
      {
        alertId: 'invalid-source',
        action: 'block',
        reason: 'sql-injection: test evidence',
      },
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
  const responderEvents = responderLog
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  assert.ok(
    responderEvents.some((event) =>
      event.alertId === 'invalid-source'
      && event.action === 'block'
      && event.outcome === 'skipped_invalid_source'
    ),
    'invalid source is logged and skipped'
  );

  console.log('실행기 반복 집계 확인: 동일 출처의 단일 강한 패턴 경보에서 고유 ID 반복을 차단 근거로 사용하며 marker/설명/count는 공격 신호가 아님');
  for (const decision of result.decisions) console.log(`${decision.alertId} | ${decision.action}`);
  console.log(`집계: block ${result.counts.block} / alert ${result.counts.alert} / record ${result.counts.record}`);
  console.log('응답기 확인: 유효한 대체 출처 필드에서 후보 생성, 잘못된 IP 출처는 거부');
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
