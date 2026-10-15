import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/restore.js';

function mockResponse() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
  };
}

test('복구 API는 POST 이외의 요청을 거부한다', async () => {
  const response = mockResponse();

  await handler({ method: 'GET', headers: {} }, response);

  assert.equal(response.statusCode, 405);
  assert.deepEqual(response.body, { error: 'METHOD_NOT_ALLOWED' });
  assert.equal(response.headers.allow, 'POST');
  assert.equal(response.headers['cache-control'], 'no-store, max-age=0');
});

test('복구 API는 필수 입력이 없는 요청을 거부한다', async () => {
  const response = mockResponse();

  await handler({ method: 'POST', headers: {}, body: {} }, response);

  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.body, { error: 'INVALID_RESTORE_REQUEST' });
});

test('복구 API는 인증 정보가 없는 요청을 거부한다', async () => {
  const response = mockResponse();
  const body = {
    id: '123',
    ownerId: '11111111-1111-4111-8111-111111111111',
    contentSha256: 'a'.repeat(64),
  };

  await handler({ method: 'POST', headers: {}, body }, response);

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.body, { error: 'AUTHENTICATION_REQUIRED' });
});

test('복구 API는 Bearer 형식이 아닌 인증 정보를 거부한다', async () => {
  const response = mockResponse();
  const body = {
    id: '123',
    ownerId: '11111111-1111-4111-8111-111111111111',
    contentSha256: 'a'.repeat(64),
  };

  await handler({
    method: 'POST',
    headers: { authorization: 'invalid-token' },
    body,
  }, response);

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.body, { error: 'AUTHENTICATION_REQUIRED' });
});
