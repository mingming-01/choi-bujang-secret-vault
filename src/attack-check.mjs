export async function runAttackChecks(config) {
  if (config.step !== 3) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (app.protocol !== 'https:' || app.username || app.password || app.search
      || app.hash || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const results = [];
  const options = { redirect: 'error', signal: AbortSignal.timeout(10000) };
  const homepage = await fetch(new URL('/', app), options);
  results.push({
    attackId: 'homepage_nosniff_header',
    expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 있어야 함',
    observed: homepage.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
      ? `첫 화면 HTTP${homepage.status}에서 nosniff 헤더를 확인함`
      : `첫 화면 HTTP${homepage.status}에서 nosniff 헤더를 확인하지 못함`,
  });

  const dataResponse = await fetch(new URL('/data.json', app), options);
  results.push({
    attackId: 'anonymous_static_note_read',
    expected: '정적 /data.json은 배포되지 않아야 함',
    observed: dataResponse.status === 404
      ? '비로그인 요청에서 /data.json이 404로 응답함'
      : `/data.json이 HTTP${dataResponse.status}로 응답함`,
  });

  const apiResponse = await fetch(new URL('/api/notes', app), options);
  let jsonError = false;
  try {
    const contentType = apiResponse.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await apiResponse.json() : null;
    jsonError = typeof data?.error === 'string';
  } catch {
    // JSON 아닌 응답은 비로그인 JSON 거부로 세지 않습니다.
  }
  results.push({
    attackId: 'anonymous_api_note_read',
    expected: '비로그인 /api/notes 요청은 HTTP 401/403 및 JSON 오류로 차단되어야 함',
    observed: (apiResponse.status === 401 || apiResponse.status === 403) && jsonError
      ? `비로그인 요청이 HTTP${apiResponse.status} JSON 오류로 차단됨`
      : `비로그인 요청 HTTP${apiResponse.status}; JSON 오류 응답=${jsonError}`,
  });

  const identityResponse = await fetch(new URL('/aleph.json', app), options);
  results.push({
    attackId: 'deployment_identity_available',
    expected: '/aleph.json을 계속 제공해야 함',
    observed: identityResponse.ok
      ? `/aleph.json이 HTTP${identityResponse.status}로 제공됨`
      : `/aleph.json이 HTTP${identityResponse.status}로 제공되지 않음`,
  });

  return results;
}
