export async function runAttackChecks(config) {
  if (config.step !== 2) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (
    app.protocol !== 'https:' ||
    app.username ||
    app.password ||
    app.search ||
    app.hash ||
    app.pathname !== '/' ||
    app.hostname.endsWith('.example')
  ) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const results = [];

  const dataResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  results.push({
    attackId: 'anonymous_static_note_read',
    expected: '비로그인 요청으로 /data.json에서 가상 메모를 읽을 수 없어야 함',
    observed: dataResponse.status === 404
      ? '비로그인 요청에서 /data.json이 404로 차단됨'
      : `비로그인 요청에서 /data.json이 HTTP${dataResponse.status}로 응답함`,
  });

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let apiVisible = false;

  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      apiVisible = Array.isArray(data?.notes);
    } catch {
      // A non-JSON response is not considered a successful API read.
    }
  }

  results.push({
    attackId: 'anonymous_api_note_read',
    expected: '비로그인 요청으로 /api/notes를 호출할 수 있음을 확인하고 공개 API 약점을 기록',
    observed: apiVisible
      ? '비로그인 요청에서 /api/notes 응답을 확인함'
      : `비로그인 요청에서 /api/notes 응답을 확인하지 못함 (HTTP${apiResponse.status})`,
  });

  return results;
}