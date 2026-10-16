import assert from 'node:assert/strict';
import test from 'node:test';
import { createEvidenceRecord, summarizeEvidence } from '../public/war-room-evidence.js';

const base = {
  label: '인증 없는 조회 차단', method: 'GET', path: '/api/notes',
  expectedStatus: 401, expectedCode: 'AUTHENTICATION_REQUIRED',
  clientRequestId: 'client-test-id', checkedAt: '2026-10-16T00:00:00.000Z',
};

test('실제 API 응답이 기대 상태와 오류 코드에 맞으면 일치로 기록한다', () => {
  const row = createEvidenceRecord({ ...base, responseStatus: 401, responseCode: 'AUTHENTICATION_REQUIRED' });
  assert.equal(row.verdict, '일치');
  assert.equal(row.requestId, 'client-test-id');
  assert.equal(row.requestIdSource, 'client');
  assert.equal(row.actual, 'HTTP 401 · AUTHENTICATION_REQUIRED');
});

test('기대와 다른 HTTP 결과는 일치로 처리하지 않는다', () => {
  const row = createEvidenceRecord({ ...base, responseStatus: 200, responseCode: null });
  assert.equal(row.verdict, '불일치');
});

test('HTTP 응답이 없으면 미검증으로 남기고 서버 요청 ID를 우선한다', () => {
  const pending = createEvidenceRecord({ ...base, error: 'DEVICE_NOT_APPROVED' });
  assert.equal(pending.verdict, '미검증');
  const response = createEvidenceRecord({ ...base, responseStatus: 401, responseCode: 'AUTHENTICATION_REQUIRED', responseRequestId: 'server-request-1' });
  assert.equal(response.requestId, 'server-request-1');
  assert.equal(response.requestIdSource, 'server');
});

test('요약은 일치·불일치·미검증 건수를 구분한다', () => {
  const rows = [
    createEvidenceRecord({ ...base, responseStatus: 401, responseCode: 'AUTHENTICATION_REQUIRED' }),
    createEvidenceRecord({ ...base, responseStatus: 200 }),
    createEvidenceRecord({ ...base, error: 'request_not_sent' }),
  ];
  assert.deepEqual(summarizeEvidence(rows), { total: 3, matched: 1, mismatched: 1, unverified: 1 });
});
