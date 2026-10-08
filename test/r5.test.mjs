import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const config = {
  step: 2,
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

test('배포 식별 정보는 2단계 설정도 허용하고 단계 번호를 기록한다', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
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

test('2단계 화면은 서버 API를 호출하고 정적 data.json을 호출하지 않는다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /fetch\('\/api\/notes'/u);
  assert.doesNotMatch(html, /fetch\('\/data\.json'/u);
});

test('자료 API는 GET만 허용하고 설정 오류 상세를 반환하지 않는다', async () => {
  const { default: handler } = await import('../api/notes.js');
  const headers = new Map();
  let status;
  let body;
  const response = {
    setHeader: (key, value) => headers.set(key.toLowerCase(), value),
    status: value => {
      status = value;
      return { json: value => { body = value; } };
    },
  };

  handler({ method: 'POST' }, response);
  assert.equal(status, 405);
  assert.equal(headers.get('allow'), 'GET');
  assert.deepEqual(body, { error: 'METHOD_NOT_ALLOWED' });

  const originalUrl = process.env.SUPABASE_URL;
  const originalSecret = process.env.SUPABASE_SECRET_KEY;
  try {
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SECRET_KEY;
    handler({ method: 'GET' }, response);
    assert.equal(status, 500);
    assert.deepEqual(body, { error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  } finally {
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalSecret === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalSecret;
  }
});
