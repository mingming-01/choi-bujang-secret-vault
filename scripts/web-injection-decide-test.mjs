import assert from 'node:assert/strict';
import { decide } from '../xdr/web-injection/decide.mjs';

const cases = [
  {
    name: '반복 근거와 유효한 출발지 주소가 있는 SQL 구문',
    alert: {
      rule: { description: '같은 주소에서 SQL 구문 표기가 3번 반복됐습니다.' },
      data: { srcip: '203.0.113.10', url: '/search?q=union+select' },
    },
    expectedAction: 'block',
  },
  {
    name: '반복 근거가 없는 명시적 SQL 구문',
    alert: {
      rule: { description: 'SQL 구문 표기가 관찰됐습니다.' },
      data: { srcip: '203.0.113.11', url: '/search?q=union+select' },
    },
    expectedAction: 'alert',
  },
  {
    name: '반복 근거가 있어도 유효하지 않은 출발지 주소',
    alert: {
      rule: { description: '같은 주소에서 SQL 구문 표기가 3번 반복됐습니다.' },
      data: { srcip: '999.1.1.1', url: '/search?q=union+select' },
    },
    expectedAction: 'alert',
  },
  {
    name: '정상 검색 요청',
    alert: {
      rule: { description: '검색어를 조회했습니다.' },
      data: { srcip: '203.0.113.12', url: '/search?q=select-course' },
    },
    expectedAction: 'record',
  },
];

for (const { name, alert, expectedAction } of cases) {
  const result = decide(alert);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
  assert.equal(result.action, expectedAction, name);
  assert.equal(typeof result.confidence, 'number', name);
  assert.equal(typeof result.reason, 'string', name);
}

console.log(`독립 decide 테스트 케이스 ${cases.length}개 정의됨`);
