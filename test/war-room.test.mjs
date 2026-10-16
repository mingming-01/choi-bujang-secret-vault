import assert from 'node:assert/strict';
import test from 'node:test';
import { createWarRoomHandler } from '../api/war-room.js';

function makeResponse() {
  return {
    headers: {},
    statusCode: 200,
    body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

function makeRuntime(rows = [{ status: 'approved' }, { status: 'pending' }]) {
  const query = {
    select() { return this; },
    eq() { return this; },
    then(resolve, reject) {
      return Promise.resolve({ data: rows, error: null }).then(resolve, reject);
    },
  };
  return {
    verifyLogin: async () => ({ kind: 'student', userId: 'student-1' }),
    supabase: { from(table) { assert.equal(table, 'device_credentials'); return query; } },
  };
}

test('탈환 작전실은 인증되지 않은 요청을 거부한다', async () => {
  const handler = createWarRoomHandler({ runtimeProvider: () => makeRuntime() });
  const response = makeResponse();
  await handler({ method: 'GET', headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'AUTHENTICATION_REQUIRED');
});

test('요약에는 실제 규칙·상태만 담고 메모 본문을 노출하지 않는다', async () => {
  const privateBody = 'DO_NOT_EXPOSE_PRIVATE_NOTE_BODY';
  const handler = createWarRoomHandler({
    runtimeProvider: () => makeRuntime(),
    ruleIds: ['device_registered', 'step_up_required', 'resource_zone_access'],
    backupLoader: async () => ({
      backup: { ownerId: 'student-1', revision: 'backup-r7', title: 'PRIVATE_TITLE', content: privateBody },
      backupSha256: 'a'.repeat(64),
    }),
  });
  const response = makeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer a.b.c' } }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.decision.ruleIds, [
    'device_registered', 'step_up_required', 'resource_zone_access',
  ]);
  assert.equal(response.body.deviceApproval.counts.approved, 1);
  assert.equal(response.body.deviceApproval.counts.pending, 1);
  assert.equal(response.body.recovery.revision, 'backup-r7');
  assert.equal(response.body.detection.eventCount, null);
  assert.equal(response.body.revocation.status, 'not_executed');
  assert.equal(response.body.serverRecords.count, null);
  assert.equal(JSON.stringify(response.body).includes(privateBody), false);
  assert.equal(JSON.stringify(response.body).includes('PRIVATE_TITLE'), false);
  assert.equal(JSON.stringify(response.body).includes('student-1'), false);
});

test('다른 소유자의 백업 버전은 요약에 포함하지 않는다', async () => {
  const handler = createWarRoomHandler({
    runtimeProvider: () => makeRuntime([]),
    backupLoader: async () => ({
      backup: { ownerId: 'another-student', revision: 'backup-private-r8', content: 'PRIVATE' },
      backupSha256: 'b'.repeat(64),
    }),
  });
  const response = makeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer a.b.c' } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.recovery.status, 'not_available_for_user');
  assert.equal(JSON.stringify(response.body).includes('backup-private-r8'), false);
});
