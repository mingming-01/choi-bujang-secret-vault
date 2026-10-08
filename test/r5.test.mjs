import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const config = {
  step: 3,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

function mockResponse() {
  const headers = new Map();
  let status;
  let body;
  return {
    headers,
    get statusCode() { return status; },
    get body() { return body; },
    setHeader: (key, value) => headers.set(key.toLowerCase(), value),
    status: value => { status = value; return { json: value => { body = value; } }; },
  };
}

test('배포 식별 정보는 3단계 설정도 허용하고 단계 번호를 기록한다', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.throws(() => deploymentIdentity(env, { ...config, step: 13 }));
});

test('3단계 화면은 공식 SDK 인증 UI와 API 흐름을 제공하고 정적 data.json을 호출하지 않는다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /@supabase\/supabase-js/u);
  assert.match(html, /signInWithPassword/u);
  assert.match(html, /signOut/u);
  assert.match(html, /fetch\('\/api\/notes'/u);
  assert.doesNotMatch(html, /fetch\('\/data\.json'/u);
  assert.match(html, /Authorization: `Bearer \$\{session\.access_token\}`/u);
});

test('메모 목록 API는 인증 없는 요청을 HTTP 401 및 JSON 오류로 거부한다', async () => {
  const { default: handler } = await import('../api/notes.js');
  const response = mockResponse();
  await handler({ method: 'GET', headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(response.headers.get('cache-control'), 'no-store, max-age=0');
  assert.deepEqual(response.body, { error: 'AUTHENTICATION_REQUIRED' });
});

test('목록 API는 JWT 모양이 아닌 Bearer 문자열도 JSON 401로 거부한다', async () => {
  const { default: handler } = await import('../api/notes.js');
  const response = mockResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer invalid.token.value' } }, response);
  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.body, { error: 'INVALID_AUTHENTICATION' });
});

test('메모 단건 API도 토큰 없는 GET을 JSON 401로 거부한다', async () => {
  const { default: handler } = await import('../api/notes/[id].js');
  const response = mockResponse();
  await handler({ method: 'GET', query: { id: '11111111-1111-4111-8111-111111111111' }, headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.body, { error: 'AUTHENTICATION_REQUIRED' });
});

test('Supabase 설정과 허용 경로는 secret을 포함하지 않고 Supabase Auth 발급자와 일치한다', async () => {
  const settings = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  assert.equal(settings.step, 3);
  assert.deepEqual(settings.allowedRoutes, [
    '/api/notes (GET, POST)',
    '/api/notes/:id (GET, PUT, DELETE)',
  ]);
  assert.equal(settings.identityProvider.issuer, 'https://gxqfisevuianuyaahqlu.supabase.co/auth/v1');
  assert.equal(settings.identityProvider.audience, 'authenticated');
  assert.equal(settings.identityProvider.jwksUrl,
    `${settings.identityProvider.issuer}/.well-known/jwks.json`);
  assert.doesNotMatch(JSON.stringify(settings.identityProvider), /secret|service_role|sb_secret/iu);
});

test('SQL 준비 파일은 기존 학습 자료를 바꾸지 않고 사용자 메모 테이블만 준비한다', async () => {
  const sql = await readFile(new URL('../supabase/step-3-user-notes.sql', import.meta.url), 'utf8');
  assert.match(sql, /create table if not exists public\.user_notes/u);
  assert.match(sql, /owner_id uuid not null/u);
  assert.match(sql, /alter table public\.user_notes enable row level security/u);
  assert.match(sql, /revoke all privileges on table public\.user_notes from public, anon, authenticated/u);
  assert.doesNotMatch(sql, /drop table|delete from public\.learning_notes|truncate public\.learning_notes/iu);
});

test('단건 PUT과 DELETE도 인증 없이 메모에 접근할 수 없다', async () => {
  const { default: handler } = await import('../api/notes/[id].js');
  const id = '11111111-1111-4111-8111-111111111111';
  for (const method of ['PUT', 'DELETE']) {
    const response = mockResponse();
    await handler({ method, query: { id }, headers: {}, body: { title: 'sample', body: 'sample' } }, response);
    assert.equal(response.statusCode, 401);
    assert.equal(typeof response.body.error, 'string');
  }
});

test('신규 메모 owner_id는 서버 검증자에서만 제공되고 단건 경로에는 owner 필터가 없다', async () => {
  const collection = await readFile(new URL('../api/notes.js', import.meta.url), 'utf8');
  const single = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
  assert.match(collection, /owner_id:\s*user\.userId/u);
  assert.doesNotMatch(collection, /body\.owner_id/u);
  assert.match(collection, /createLoginVerifier/u);
  assert.match(single, /createLoginVerifier/u);
  assert.match(single, /\.eq\('id', id\)/u);
  assert.doesNotMatch(single, /\.eq\('owner_id'/u);
});
