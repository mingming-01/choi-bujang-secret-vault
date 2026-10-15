import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRestoreHandler } from '../api/restore.js';

const hash = (value) =>
  createHash('sha256').update(value).digest('hex');

const backup = {
  schema: 'aleph.note-backup.v1',
  environment: 'production-backup',
  revision: 'restore-test-v1',
  id: '100001',
  ownerId: '20000000-0000-4000-8000-000000000002',
  title: '복구 대상 메모',
  content: '백업에서 복구할 내용',
  contentSha256: hash('백업에서 복구할 내용'),
};

function createDatabase(initialRows = []) {
  const rows = structuredClone(initialRows);
  const writes = [];

  const client = {
    from(table) {
      if (table !== 'learning_notes') {
        throw new Error(`허용되지 않은 테이블 접근: ${table}`);
      }

      let operation = 'select';
      let payload;
      const filters = [];

      const query = {
        select() {
          return query;
        },

        insert(value) {
          operation = 'insert';
          payload = value;
          return query;
        },

        update(value) {
          operation = 'update';
          payload = value;
          return query;
        },

        eq(column, value) {
          filters.push([column, value]);
          return query;
        },

        async maybeSingle() {
          const matches = (row) =>
            filters.every(([key, value]) => row[key] === value);

          if (operation === 'select') {
            const row = rows.find(matches);
            return {
              data: row ? structuredClone(row) : null,
              error: null,
            };
          }

          if (operation === 'insert') {
            if (rows.some((row) => row.id === payload.id)) {
              return {
                data: null,
                error: { message: 'duplicate id' },
              };
            }

            rows.push(structuredClone(payload));
            writes.push({ operation, id: payload.id });

            return {
              data: { id: payload.id },
              error: null,
            };
          }

          if (operation === 'update') {
            const row = rows.find(matches);

            if (!row) {
              return { data: null, error: null };
            }

            Object.assign(row, structuredClone(payload));
            writes.push({ operation, id: row.id });

            return {
              data: { id: row.id },
              error: null,
            };
          }

          throw new Error(`알 수 없는 작업: ${operation}`);
        },
      };

      return query;
    },
  };

  return { client, rows, writes };
}

function createResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,

    setHeader(name, value) {
      this.headers[name] = value;
    },

    status(code) {
      this.statusCode = code;
      return this;
    },

    json(value) {
      this.body = value;
      return this;
    },

    end() {
      return this;
    },
  };
}

function createRequest(body, method = 'POST') {
  return {
    method,
    headers: { authorization: 'Bearer test-token' },
    body,
  };
}

function createHarness(initialRows = []) {
  const db = createDatabase(initialRows);

  const handler = createRestoreHandler({
    runtimeProvider: () => ({
      supabase: db.client,
      verifyLogin: async () => ({
        kind: 'judge',
        identity: 'b',
        userId: '30000000-0000-4000-8000-000000000003',
      }),
    }),

    backupLoader: async () => ({
      backup: structuredClone(backup),
      backupSha256: hash(JSON.stringify(backup)),
    }),
  });

  const body = {
    id: backup.id,
    ownerId: backup.ownerId,
    contentSha256: backup.contentSha256,
  };

  async function call(requestBody) {
    const response = createResponse();
    await handler(createRequest(requestBody), response);
    return response;
  }

  return { db, body, call };
}

test('백업 미리보기는 데이터를 변경하지 않는다', async () => {
  const original = {
    id: backup.id,
    owner_id: backup.ownerId,
    title: '기존 제목',
    content: '기존 내용',
  };

  const harness = createHarness([
    original,
    {
      id: '100002',
      owner_id: 'another-owner',
      title: '다른 메모',
      content: '유지되어야 할 내용',
    },
  ]);

  const response = await harness.call(harness.body);

  assert.equal(response.statusCode, 200);
  assert.ok(response.body.preview);
  assert.deepEqual(harness.db.writes, []);
  assert.equal(harness.db.rows[0].content, '기존 내용');
  assert.equal(harness.db.rows[1].content, '유지되어야 할 내용');
});

test('확인값이 없거나 오래된 경우 복원하지 않는다', async () => {
  const harness = createHarness([{
    id: backup.id,
    owner_id: backup.ownerId,
    title: '기존 제목',
    content: '기존 내용',
  }]);

  const previewResponse = await harness.call(harness.body);
  const confirmation = previewResponse.body.preview.confirmation;

  const staleResponse = await harness.call({
    ...harness.body,
    confirmation: `${confirmation}-stale`,
  });

  assert.equal(staleResponse.statusCode, 409);
  assert.equal(
    staleResponse.body.error,
    'RESTORE_CONFIRMATION_REQUIRED',
  );
  assert.deepEqual(harness.db.writes, []);
});

test('확인된 요청은 대상 메모 한 건만 복원하고 결과를 검증한다', async () => {
  const otherNote = {
    id: '100002',
    owner_id: 'another-owner',
    title: '보존할 메모',
    content: '이 내용은 바뀌면 안 된다',
  };

  const harness = createHarness([
    {
      id: backup.id,
      owner_id: backup.ownerId,
      title: '기존 제목',
      content: '기존 내용',
    },
    otherNote,
  ]);

  const previewResponse = await harness.call(harness.body);
  const confirmation = previewResponse.body.preview.confirmation;

  const restoreResponse = await harness.call({
    ...harness.body,
    confirmation,
  });

  assert.equal(restoreResponse.statusCode, 200);
  assert.equal(restoreResponse.body.restored, true);

  const restored = harness.db.rows.find((row) => row.id === backup.id);

  assert.equal(restored.id, backup.id);
  assert.equal(restored.owner_id, backup.ownerId);
  assert.equal(restored.title, backup.title);
  assert.equal(hash(restored.content), backup.contentSha256);

  assert.deepEqual(harness.db.rows[1], otherNote);
  assert.equal(harness.db.writes.length, 1);
  assert.equal(harness.db.writes[0].id, backup.id);
});

test('백업 검증에 실패하면 데이터 변경 없이 중단한다', async () => {
  const harness = createHarness([{
    id: backup.id,
    owner_id: backup.ownerId,
    title: '기존 제목',
    content: '기존 내용',
  }]);

  const handler = createRestoreHandler({
    runtimeProvider: () => ({
      supabase: harness.db.client,
      verifyLogin: async () => ({
        kind: 'judge',
        identity: 'b',
        userId: '30000000-0000-4000-8000-000000000003',
      }),
    }),

    backupLoader: async () => {
      throw new Error('S10_BACKUP_UNVERIFIED');
    },
  });

  const response = createResponse();

  await handler(createRequest(harness.body), response);

  assert.notEqual(response.statusCode, 200);
  assert.deepEqual(harness.db.writes, []);
  assert.equal(harness.db.rows[0].content, '기존 내용');
});