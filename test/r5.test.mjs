import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const config = {
  step: 5,
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

test('배포 식별 정보는 5단계 설정도 허용하고 단계 번호를 기록한다', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 5,
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

test('5단계 화면은 서버 인증 API와 보호된 메모 API를 사용하고 Supabase Auth를 직접 호출하지 않는다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');

  assert.match(html, /fetch\(['"]\/api\/auth['"]/u);
  assert.match(html, /fetch\(['"]\/api\/notes['"]/u);
  assert.doesNotMatch(html, /@supabase\/supabase-js/u);
  assert.doesNotMatch(html, /signInWithPassword/u);
  assert.doesNotMatch(html, /supabase\.auth/u);
  assert.doesNotMatch(html, /sb_publishable_/u);
  assert.doesNotMatch(html, /SUPABASE_PUBLISHABLE_KEY/u);
  assert.doesNotMatch(html, /SUPABASE_ANON_KEY/u);
  assert.doesNotMatch(html, /data\.json/u);
  assert.match(html, /Authorization:\s*`Bearer \$\{session\.access_token\}`/u);
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
  assert.equal(settings.step, 5);
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

test('기존 learning_notes와 CRUD user_notes 구조를 보존하는 SQL 파일이 준비되어 있다', async () => {
  const seedSql = await readFile(new URL('../supabase/step-4-owned-notes-seed.sql', import.meta.url), 'utf8');
  const policySql = await readFile(new URL('../supabase/step-4-user-notes-rls.sql', import.meta.url), 'utf8');
  assert.match(seedSql, /lower\(email\) = lower\('gjals0318@gmail\.com'\)/u);
  assert.match(seedSql, /lower\(email\) = lower\('example@gmail\.com'\)/u);
  assert.match(seedSql, /set owner_id = a_user_id/u);
  assert.match(seedSql, /values \(b_user_id, sample_title, sample_content\)/u);
  assert.doesNotMatch(seedSql, /auth\.users[\s\S]{0,100}references/iu);
  for (const table of ['learning_notes', 'user_notes']) {
    assert.match(policySql, new RegExp(`alter table public\\.${table} enable row level security`, 'u'));
    assert.match(policySql, new RegExp(`revoke all privileges on table public\\.${table}`, 'u'));
  }

  assert.match(
    policySql,
    /grant select on table public\.learning_notes to authenticated/u
  );

  assert.match(
    policySql,
    /grant select, insert, update, delete on table public\.user_notes to authenticated/u
  );
  assert.match(policySql, /using \(auth\.uid\(\) = owner_id\)/u);
  assert.match(policySql, /with check \(auth\.uid\(\) = owner_id\)/u);
  assert.match(policySql, /information_schema\.role_table_grants/u);
  assert.match(policySql, /has_table_privilege/u);
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

test('모든 사용자 메모 경로는 검증된 소유자 ID로 필터링하고 소유권 변경을 허용하지 않는다', async () => {
  const collection = await readFile(new URL('../api/notes.js', import.meta.url), 'utf8');
  const single = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
  assert.match(collection, /createLoginVerifier/u);
  assert.match(single, /createLoginVerifier/u);
  assert.match(collection, /\.eq\('owner_id', user\.userId\)/u);
  assert.match(collection, /owner_id:\s*user\.userId/u);
  assert.doesNotMatch(collection, /body\.owner_id/u);
  assert.match(single, /\.eq\('id', id\)[\s\S]*?\.eq\('owner_id', user\.userId\)/u);
  assert.match(single, /\.update\(\{ owner_id: user\.userId,/u);
  assert.match(single, /\.delete\(\)[\s\S]*?\.eq\('owner_id', user\.userId\)/u);
  assert.doesNotMatch(single, /request\.body\.owner_id|body\.owner_id/u);
});

test('3단계 보안 헤더와 /data.json 차단 빌드 동작을 보존한다', async () => {
  const vercel = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  const build = await readFile(new URL('../scripts/build-public.mjs', import.meta.url), 'utf8');
  assert.ok(vercel.headers.some(rule => rule.source === '/' && rule.headers.some(header =>
    header.key === 'X-Content-Type-Options' && header.value === 'nosniff')));
  assert.match(build, /config\.step === 1/u);
  assert.match(build, /await unlink\(output\)/u);
  assert.match(build, /public', 'aleph\.json'/u);
});

test('서버 인증 API는 로그인·갱신·로그아웃을 위한 POST, PUT, DELETE만 허용한다', async () => {
  const { default: handler } = await import('../api/auth.js');

  for (const method of ['GET', 'PATCH']) {
    const response = mockResponse();

    await handler({
      method,
      headers: {},
    }, response);

    assert.equal(response.statusCode, 405);
    assert.deepEqual(response.body, { error: 'METHOD_NOT_ALLOWED' });
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  }
});
