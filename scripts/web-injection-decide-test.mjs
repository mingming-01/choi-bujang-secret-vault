import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/web-injection/decide.mjs';

const decidePath = fileURLToPath(new URL('../xdr/web-injection/decide.mjs', import.meta.url));
const source = await readFile(decidePath, 'utf8');
assert.equal(/^\s*import\s/m.test(source), false, 'decide.mjs must have no imports');
assert.equal(/\b(?:readFile|writeFile|appendFile|fetch)\s*\(/.test(source), false, 'decide.mjs must not perform I/O');

const fixturePath = fileURLToPath(new URL('../xdr/fixtures/web-injection.json', import.meta.url));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
assert.equal(fixture.moduleKey, 'web-injection');

// Fixture descriptions are metadata, not substitutes for request payloads or separate events.
const expected = new Map([
  ...['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08', 'wi-09', 'wi-15', 'wi-16', 'wi-17']
    .map((id) => [id, 'alert']),
  ...['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']
    .map((id) => [id, 'record']),
]);

const counts = { block: 0, alert: 0, record: 0 };
for (const alert of fixture.alerts) {
  const expectedAction = expected.get(alert.id);
  assert.ok(expectedAction, `missing evidence-based expectation for ${alert.id}`);
  const result = decide(alert);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason'], alert.id);
  assert.equal(result.action, expectedAction, `${alert.id}: data.url has no actual SQL syntax, script tag, or ../ traversal`);
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
  assert.equal(decide(flattenedAlert).action, expectedAction, `top-level description for ${alert.id}`);
}
assert.equal(expected.size, fixture.alerts.length, 'all fixture IDs have independent expectations');
assert.deepEqual(counts, { block: 0, alert: 12, record: 14 });

const singleSql = {
  id: 'standalone-sql',
  rule: { description: '요청에서 의심 구문이 관찰됐습니다.' },
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users', count: '99' },
};
assert.equal(decide(singleSql).action, 'alert', 'data.count must not establish repetition');
assert.equal(decide({
  rule: { description: '같은 주소에서 SQL 구문이 3번 반복됐습니다.' },
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users', count: '1' },
}).action, 'alert', 'a single event description cannot establish separate-alert repetition');
assert.equal(decide({
  correlationEvidence: { sourceAddress: '203.0.113.90', patternId: 'sql-injection', occurrences: 2 },
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users' },
}).action, 'block', 'explicit repeated same-source and same-pattern correlation may block');
assert.equal(decide({
  correlationEvidence: { sourceAddress: '203.0.113.90', patternId: 'sql-injection', occurrences: 2 },
  data: { srcip: '198.51.100.90', url: '/search?q=union+select+name+from+users' },
}).action, 'alert', 'correlation for a different source must not block');
assert.equal(decide({
  correlationEvidence: { sourceAddress: '203.0.113.90', patternId: 'sql-injection', occurrences: 2 },
  data: { srcip: '203.0.113.90', url: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' },
}).action, 'alert', 'correlation for another pattern must not block');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' },
}).action, 'alert', 'an actual one-off script tag is suspicious, not a block');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/files?path=../../etc/passwd' },
}).action, 'alert', 'an actual one-off traversal string is suspicious, not a block');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=select-script-up' },
  rule: { description: '일반 검색입니다. SQL 수업의 script 단어와 up이 포함됐습니다.' },
}).action, 'record', 'keywords alone are not attack evidence');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users+%3Cscript%3E' },
}).action, 'alert', 'overlapping attack patterns remain ambiguous');

console.log(`독립 decide 테스트 통과: fixture ${fixture.alerts.length}개와 반복·중첩 경계 사례`);
console.log(`fixture 집계: block ${counts.block} / alert ${counts.alert} / record ${counts.record}`);
