import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/web-injection/decide.mjs';

const decidePath = fileURLToPath(new URL('../xdr/web-injection/decide.mjs', import.meta.url));
const source = await readFile(decidePath, 'utf8');
assert.equal(/^\s*import\s/m.test(source), false, 'decide.mjs must have no imports');
assert.equal(/\b(?:readFile|writeFile|appendFile|fetch)\s*\(/.test(source), false, 'decide.mjs must not perform I/O');
assert.deepEqual([...source.matchAll(/export\s+(?:async\s+)?function\s+(\w+)/g)].map((match) => match[1]), ['decide'], 'decide must be the only public function');
assert.equal(/doc-(?:sql|script|up)-/.test(source), false, 'synthetic doc markers must not be attack patterns');

const fixturePath = fileURLToPath(new URL('../xdr/fixtures/web-injection.json', import.meta.url));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
assert.equal(fixture.moduleKey, 'web-injection');

// Fixture classifications are based on request evidence and the explicit
// high-risk review metadata rule, never on descriptions or count fields.
const expected = new Map([
  ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08']
    .map((id) => [id, 'alert']),
  ...['wi-09', 'wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-15', 'wi-16', 'wi-17', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
    .map((id) => [id, 'record']),
]);

const counts = { block: 0, alert: 0, record: 0 };
for (const alert of fixture.alerts) {
  const expectedAction = expected.get(alert.id);
  assert.ok(expectedAction, `missing expectation for ${alert.id}`);
  const result = decide(alert);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason'], alert.id);
  assert.equal(result.action, expectedAction, `${alert.id}: expected fixture classification`);
  assert.equal(typeof result.confidence, 'number', alert.id);
  assert.equal(typeof result.reason, 'string', alert.id);
  if (result.action === 'block') assert.ok(result.confidence >= 0.85, alert.id);
  if (result.action === 'alert') assert.ok(result.confidence >= 0.5 && result.confidence < 0.85, alert.id);
  if (result.action === 'record') assert.ok(result.confidence < 0.5, alert.id);
  counts[result.action] += 1;

  const flattenedAlert = {
    ...alert,
    description: alert.rule.description,
    rule: { ...alert.rule, description: undefined },
  };
  assert.equal(decide(flattenedAlert).action, expectedAction, `description does not change classification for ${alert.id}`);
}
assert.equal(expected.size, fixture.alerts.length);
assert.deepEqual(counts, { block: 0, alert: 8, record: 18 }, 'direct single-alert fixture classifications');

const sqlUrl = '/search?q=union+select+name+from+users';
const correlated = (id, url = sqlUrl, sourceAddress = 'ipv4:203.0.113.90', patternId = 'sql-injection') => ({
  id,
  data: { srcip: '203.0.113.90', url },
  correlationEvidence: { sourceAddress, patternId, alertIds: [id, `${id}-peer`] },
});

const sqlAlert = {
  id: 'standalone-sql',
  data: { srcip: '203.0.113.90', url: sqlUrl, count: '99' },
};
assert.equal(decide(sqlAlert).action, 'alert', 'one actual SQL pattern remains alert-only regardless of data.count');
assert.equal(decide({
  ...sqlAlert,
  rule: { description: '같은 주소에서 SQL 구문이 3번 반복됐습니다.' },
  data: { ...sqlAlert.data, count: '1' },
}).action, 'alert', 'description claims cannot establish repetition');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=doc-sql-chain', count: '3' },
}).action, 'record', 'synthetic doc marker and count are not attack evidence');
for (const word of ['select-course', 'script-class', 'up-notes', 'sql-class']) {
  assert.equal(decide({ data: { srcip: '203.0.113.90', url: `/search?q=${word}` } }).action, 'record', `${word} alone is not an attack pattern`);
}

assert.equal(decide(correlated('sql-event-a')).action, 'block', 'two distinct same-source same-pattern alert IDs permit blocking');
assert.equal(decide({
  ...correlated('wrong-source'),
  data: { srcip: '198.51.100.90', url: sqlUrl },
}).action, 'alert', 'correlation evidence for another source cannot block');
assert.equal(decide({
  ...sqlAlert,
  id: 'duplicate-id',
  correlationEvidence: { sourceAddress: 'ipv4:203.0.113.90', patternId: 'sql-injection', alertIds: ['duplicate-id', 'duplicate-id'] },
}).action, 'alert', 'duplicate IDs do not prove separate alerts');
assert.equal(decide({
  ...correlated('wrong-pattern'),
  correlationEvidence: { ...correlated('wrong-pattern').correlationEvidence, patternId: 'script-tag' },
}).action, 'alert', 'correlation evidence for another pattern cannot block');
assert.equal(decide({
  ...correlated('extra-correlation-field'),
  correlationEvidence: { ...correlated('extra-correlation-field').correlationEvidence, count: 2 },
}).action, 'alert', 'unrecognized correlation fields are rejected');

const scriptUrl = '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E';
assert.equal(decide({ data: { srcip: '203.0.113.90', url: scriptUrl } }).action, 'alert', 'one actual script tag remains alert-only');
assert.equal(decide(correlated('script-event', scriptUrl, 'ipv4:203.0.113.90', 'script-tag')).action, 'block', 'repeated same-source script-tag alerts may block');
const traversalUrl = '/files?path=../../etc/passwd';
assert.equal(decide({ data: { srcip: '203.0.113.90', url: traversalUrl } }).action, 'alert', 'repeated ../ needs separate-alert correlation before block');
assert.equal(decide(correlated('traversal-event', traversalUrl, 'ipv4:203.0.113.90', 'path-traversal')).action, 'block', 'repeated same-source path-traversal alerts may block');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/files?path=../etc/passwd' },
}).action, 'alert', 'a single ../ is an incomplete request signal and remains review-only');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: "/search?q=person's-name" },
}).action, 'alert', 'a lone quote in actual request data is review-only');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users+%3Cscript%3E' },
}).action, 'alert', 'overlapping request patterns remain ambiguous');

assert.equal(decide({
  id: 'ipv6-a',
  data: { srcip: '2001:db8::1', url: sqlUrl },
  correlationEvidence: { sourceAddress: 'ipv6:2001:0db8:0000:0000:0000:0000:0000:0001', patternId: 'sql-injection', alertIds: ['ipv6-a', 'ipv6-b'] },
}).action, 'block', 'valid IPv6 sources can be correlated');
assert.equal(decide({
  id: 'mapped-ipv6',
  data: { srcip: '::ffff:203.0.113.90', url: sqlUrl },
  correlationEvidence: { sourceAddress: 'ipv6:0000:0000:0000:0000:0000:ffff:cb00:715a', patternId: 'sql-injection', alertIds: ['mapped-ipv6', 'mapped-peer'] },
}).action, 'block', 'IPv4-embedded IPv6 normalization matches the runner');
assert.equal(decide({
  id: 'invalid-ip',
  data: { srcip: '999.1.1.1', url: sqlUrl },
  correlationEvidence: { sourceAddress: 'ipv4:999.1.1.1', patternId: 'sql-injection', alertIds: ['invalid-ip', 'peer'] },
}).action, 'alert', 'invalid source IPs cannot be blocked');

assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=select-course' },
  rule: { level: 10, mitre: ['T1190'], description: '설명은 차단 근거가 아닙니다.' },
}).action, 'alert', 'high severity and T1190 together are review-only');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=select-course' },
  rule: { level: 10, mitre: ['T1190'] },
  correlationEvidence: { sourceAddress: 'ipv4:203.0.113.90', patternId: 'sql-injection', alertIds: ['meta-only', 'peer'] },
}).action, 'alert', 'metadata cannot create attack evidence or block');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=select-course' },
  rule: { level: 10, mitre: [] },
}).action, 'record', 'high severity without T1190 is not sufficient for metadata review');

console.log(`독립 decide 테스트 계약 확인: ${fixture.alerts.length}개 fixture와 명세 경계 사례`);
console.log(`개별 fixture 직접 호출 집계: block ${counts.block} / alert ${counts.alert} / record ${counts.record}`);
