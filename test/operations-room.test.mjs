import test from 'node:test';
import assert from 'node:assert/strict';
import { createOperationsHandler } from '../api/operations.js';

function responseMock() {
  return {
    headers: {}, statusCode: 200, body: undefined,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
}

const auth = 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.signature';
const runtimeProvider = () => ({
  supabase: {},
  verifyLogin: async () => ({ kind: 'student', userId: 'fixture-user' }),
});

async function request({ method = 'GET', authorization = auth, device = { ok: true } } = {}) {
  const records = [];
  const handler = createOperationsHandler({
    runtimeProvider,
    deviceVerifier: async () => device,
    logger: record => records.push(record),
    now: () => new Date('2026-09-27T12:00:00.000Z'),
    idFactory: () => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  });
  const response = responseMock();
  await handler({ method, headers: authorization ? { authorization } : {} }, response);
  return { response, records };
}

test('작전실 요약은 API 응답과 가린 기록의 집계를 맞추고 실제 미실행을 명시한다', async () => {
  const { response, records } = await request();
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.schema, 'aleph.operations-room.v1');
  const summary = response.body.summary;
  const record = response.body.maskedServerRecords[0];
  assert.equal(summary.decider.rules.length, record.ruleCount);
  assert.equal(summary.decider.decisionStatus, 'not_run');
  assert.equal(summary.detection.status, 'not_run');
  assert.equal(summary.detection.incidentCount, null);
  assert.equal(summary.detection.recordCount, null);
  assert.equal(summary.recovery.status, 'not_run');
  assert.equal(summary.recovery.restoreVersion, null);
  assert.equal(record.decisionStatus, summary.decider.decisionStatus);
  assert.equal(record.detectionStatus, summary.detection.status);
  assert.equal(record.incidentCount, summary.detection.incidentCount);
  assert.equal(record.incidentRecordCount, summary.detection.recordCount);
  assert.equal(record.recoveryStatus, summary.recovery.status);
  assert.equal(record.restoreVersion, summary.recovery.restoreVersion);
  assert.deepEqual(records, [record]);
  assert.equal(JSON.stringify(response.body).includes('memo'), false);
  assert.equal(JSON.stringify(response.body).includes('body'), false);
  assert.equal(response.headers['cache-control'], 'no-store, max-age=0');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
});

test('미인증 및 미승인 기기는 작전실 요약을 받지 못한다', async () => {
  const unauthenticated = await request({ authorization: null });
  assert.equal(unauthenticated.response.statusCode, 401);
  assert.deepEqual(unauthenticated.records, []);

  const pending = await request({ device: { ok: false, status: 403, error: 'DEVICE_NOT_APPROVED' } });
  assert.equal(pending.response.statusCode, 403);
  assert.deepEqual(pending.response.body, { error: 'DEVICE_NOT_APPROVED' });
  assert.deepEqual(pending.records, []);
});

test('작전실 요약은 GET만 허용한다', async () => {
  const { response } = await request({ method: 'POST' });
  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, 'GET');
});
