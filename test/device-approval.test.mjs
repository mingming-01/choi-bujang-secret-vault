import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyDeviceRequest } from '../src/device-approval.mjs';

const config = {
  publicAppUrl: 'https://vault.example.com',
};

function digest(value) {
  return createHash('sha256')
    .update(value, 'utf8')
    .digest('base64url');
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }

  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }

  return JSON.stringify(value);
}

function fakeSupabase(challenge) {
  return {
    from(table) {
      assert.equal(table, 'device_challenges');

      const query = {
        select() { return this; },
        eq() { return this; },
        is() { return this; },
        gt() { return this; },
        async maybeSingle() {
          return { data: challenge, error: null };
        },
      };

      return query;
    },
  };
}

function makeRequest({ method, url, body, challenge }) {
  const assertion = {
    id: 'test-credential',
    rawId: 'dGVzdC1jcmVkZW50aWFs',
    response: {},
  };

  return {
    method,
    url,
    body,
    headers: {
      'x-device-challenge': challenge.challenge,
      'x-device-assertion': Buffer
        .from(JSON.stringify(assertion))
        .toString('base64url'),
    },
  };
}

function makeChallenge({ method, path, bodySha256 }) {
  return {
    id: 'test-challenge-id',
    user_id: 'test-user',
    purpose: 'request',
    challenge: 'test-one-time-challenge',
    request_method: method,
    request_path: path,
    request_body_sha256: bodySha256,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    used_at: null,
  };
}

test('서명 헤더가 없는 보호 요청은 거부한다', async () => {
  const result = await verifyDeviceRequest({
    method: 'GET',
    url: '/api/notes',
    headers: {},
  }, {
    supabase: fakeSupabase(null),
    userId: 'test-user',
    config,
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(result.error, 'DEVICE_SIGNATURE_REQUIRED');
});

test('서명 후 요청 경로가 바뀌면 거부한다', async () => {
  const challenge = makeChallenge({
    method: 'GET',
    path: '/api/notes/12345678-1234-4123-8123-123456789abc',
    bodySha256: digest(''),
  });

  const result = await verifyDeviceRequest(
    makeRequest({
      method: 'GET',
      url: '/api/notes',
      challenge,
    }),
    {
      supabase: fakeSupabase(challenge),
      userId: 'test-user',
      config,
    },
  );

  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(result.error, 'SIGNED_REQUEST_MISMATCH');
});

test('서명 후 요청 본문이 바뀌면 거부한다', async () => {
  const originalBody = {
    title: '원래 제목',
    body: '원래 본문',
  };
  const changedBody = {
    title: '변경된 제목',
    body: '원래 본문',
  };

  const challenge = makeChallenge({
    method: 'PUT',
    path: '/api/notes/12345678-1234-4123-8123-123456789abc',
    bodySha256: digest(canonicalJson(originalBody)),
  });

  const result = await verifyDeviceRequest(
    makeRequest({
      method: 'PUT',
      url: '/api/notes/12345678-1234-4123-8123-123456789abc',
      body: changedBody,
      challenge,
    }),
    {
      supabase: fakeSupabase(challenge),
      userId: 'test-user',
      config,
    },
  );

  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(result.error, 'SIGNED_REQUEST_MISMATCH');
});