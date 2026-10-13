import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/web-injection/decide.mjs';

const fixturePath = fileURLToPath(new URL('../xdr/fixtures/web-injection.json', import.meta.url));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
assert.equal(fixture.moduleKey, 'web-injection');
assert.equal(fixture.alerts.length, 26);

const expectedActions = new Map([
  ['wi-01', 'block'], ['wi-02', 'block'], ['wi-03', 'block'], ['wi-04', 'block'],
  ['wi-05', 'alert'], ['wi-06', 'alert'], ['wi-07', 'block'], ['wi-08', 'block'],
  ['wi-09', 'alert'], ['wi-10', 'record'], ['wi-11', 'record'], ['wi-12', 'record'],
  ['wi-13', 'record'], ['wi-14', 'record'], ['wi-15', 'alert'], ['wi-16', 'alert'],
  ['wi-17', 'alert'], ['wi-18', 'record'], ['wi-19', 'record'], ['wi-20', 'record'],
  ['wi-21', 'record'], ['wi-22', 'record'], ['wi-23', 'record'], ['wi-24', 'record'],
  ['wi-25', 'record'], ['wi-26', 'record'],
]);

const counts = { block: 0, alert: 0, record: 0 };
for (const alert of fixture.alerts) {
  const expectedAction = expectedActions.get(alert.id);
  assert.ok(expectedAction, `missing expected action for fixture alert ${alert.id}`);
  const result = decide(alert);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason'], alert.id);
  assert.equal(result.action, expectedAction, `fixture alert ${alert.id}`);
  assert.equal(typeof result.confidence, 'number', alert.id);
  assert.equal(typeof result.reason, 'string', alert.id);
  counts[result.action] += 1;

  // 심판이 설명을 최상위 필드로 전달하는 형식도 원본 fixture와 같은 분류여야 합니다.
  const flattenedAlert = {
    ...alert,
    description: alert.rule.description,
    rule: { ...alert.rule, description: undefined },
  };
  assert.equal(decide(flattenedAlert).action, expectedAction, `flat description for ${alert.id}`);
}

assert.deepEqual(counts, { block: 6, alert: 6, record: 14 }, 'fixture action totals');
assert.equal(expectedActions.size, fixture.alerts.length, 'every fixture alert has an expected action');

// 실행기와 동일하게 같은 IP·같은 단일 패턴의 반복만 반복 근거로 전달합니다.
const repeatedCandidate = {
  rule: { description: 'SQL 구문 표기가 관찰됐습니다.' },
  data: { srcip: '203.0.113.90', url: '/search?q=union+select' },
};
const candidate = decide(repeatedCandidate, { classifyOnly: true });
assert.equal(candidate.action, 'alert');
assert.ok(candidate.reason.startsWith('분류용 후보:'));
const patternName = candidate.reason.slice('분류용 후보:'.length).trim();
assert.equal(decide(repeatedCandidate).action, 'alert', 'a single candidate is ambiguous without repeat evidence');
assert.equal(
  decide(repeatedCandidate, { sourceRepeatCounts: { [patternName]: 2 } }).action,
  'block',
  'repeated same-source, same-pattern candidates may be blocked',
);

console.log(`독립 decide 테스트 통과: fixture ${fixture.alerts.length}건 및 동일 출발지 반복 조건; block ${counts.block} / alert ${counts.alert} / record ${counts.record}`);
