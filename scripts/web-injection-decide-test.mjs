import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/web-injection/decide.mjs';

const fixturePath = fileURLToPath(new URL('../xdr/fixtures/web-injection.json', import.meta.url));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
assert.equal(fixture.moduleKey, 'web-injection');

// Expected decisions are derived from event-local URL/description evidence, not observed output.
const expected = new Map([
  ['wi-01', { action: 'block', basis: 'clear SQL pattern + 12 same-event repeats + valid source' }],
  ['wi-02', { action: 'block', basis: 'clear script-insertion pattern + 9 same-event repeats + valid source' }],
  ['wi-03', { action: 'block', basis: 'clear path-traversal pattern + 8 same-event repeats + valid source' }],
  ['wi-04', { action: 'block', basis: 'clear SQL pattern + 20 same-event requests + valid source' }],
  ['wi-05', { action: 'alert', basis: 'SQL and script patterns overlap' }],
  ['wi-06', { action: 'alert', basis: 'command-separator clue is outside clear supported patterns' }],
  ['wi-07', { action: 'block', basis: 'clear path-deviation pattern + 14 same-event repeats + valid source' }],
  ['wi-08', { action: 'block', basis: 'clear database-query pattern + 10 same-event repeats + valid source' }],
  ['wi-09', { action: 'alert', basis: 'single quote clue explicitly has no repetition' }],
  ['wi-10', { action: 'record', basis: 'select is a course name, not SQL syntax' }],
  ['wi-11', { action: 'record', basis: 'script is a class word, not an inserted tag' }],
  ['wi-12', { action: 'record', basis: 'up is a benign path word' }],
  ['wi-13', { action: 'record', basis: 'description explicitly says no attack marker' }],
  ['wi-14', { action: 'record', basis: 'SQL is a class-notice title' }],
  ['wi-15', { action: 'alert', basis: 'one vague unusual-search clue' }],
  ['wi-16', { action: 'alert', basis: 'one injection-like clue without repetition' }],
  ['wi-17', { action: 'alert', basis: 'single delimiter clue' }],
  ['wi-18', { action: 'record', basis: 'ordinary notes-list request' }],
  ['wi-19', { action: 'record', basis: 'ordinary user search' }],
  ['wi-20', { action: 'record', basis: 'ordinary static page' }],
  ['wi-21', { action: 'record', basis: 'ordinary notes request' }],
  ['wi-22', { action: 'record', basis: 'ordinary notices request' }],
  ['wi-23', { action: 'record', basis: 'ordinary page refresh' }],
  ['wi-24', { action: 'record', basis: 'ordinary week search' }],
  ['wi-25', { action: 'record', basis: 'ordinary file-name lookup' }],
  ['wi-26', { action: 'record', basis: 'ordinary logout page' }],
]);

const counts = { block: 0, alert: 0, record: 0 };
const reported = [];
for (const alert of fixture.alerts) {
  const expectation = expected.get(alert.id);
  assert.ok(expectation, `missing evidence-based expectation for ${alert.id}`);
  const result = decide(alert);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason'], alert.id);
  assert.equal(result.action, expectation.action, `${alert.id}: ${expectation.basis}`);
  assert.equal(typeof result.confidence, 'number', alert.id);
  assert.equal(typeof result.reason, 'string', alert.id);
  if (result.action === 'block') assert.ok(result.confidence >= 0.85, alert.id);
  if (result.action === 'alert') assert.ok(result.confidence >= 0.5, alert.id);
  if (result.action === 'record') assert.ok(result.confidence < 0.5, alert.id);
  counts[result.action] += 1;
  reported.push(`${alert.id} | ${expectation.basis} | ${result.action}`);

  const flattenedAlert = {
    ...alert,
    description: alert.rule.description,
    rule: { ...alert.rule, description: undefined },
  };
  assert.equal(decide(flattenedAlert).action, expectation.action, `top-level description for ${alert.id}`);
}
assert.equal(expected.size, fixture.alerts.length, 'all fixture IDs have independent expectations');
assert.deepEqual(counts, { block: 6, alert: 6, record: 14 });
const normalIds = new Set(['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26']);
assert.equal([...normalIds].filter((id) => decide(fixture.alerts.find((alert) => alert.id === id)).action === 'block').length, 0, 'normal events never block');

const singleSql = {
  id: 'standalone-sql',
  rule: { description: '요청에서 의심 구문이 관찰됐습니다.' },
  data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users', count: '99' },
};
assert.equal(decide(singleSql).action, 'alert', 'data.count must not establish repetition');
assert.equal(decide({
  rule: { description: '같은 주소에서 SQL 구문이 3번 반복됐습니다.' },
  data: { srcip: '203.0.113.90', url: '/search?q=doc-sql-chain', count: '1' },
}).action, 'block', 'explicit event-local repeated attack evidence may block');
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

console.log(`단독 decide 테스트 통과: ${fixture.alerts.length}개 경보 및 URL/반복/중첩 경계 사례`);
for (const line of reported) console.log(line);
console.log(`집계: block ${counts.block} / alert ${counts.alert} / record ${counts.record}`);
