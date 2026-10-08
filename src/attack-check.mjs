function getAppUrl(config) {
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

  return app;
}

function requireToken(name) {
  const token = process.env[name];
  if (!token || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token)) {
    throw new Error(`${name} 환경변수에 유효한 Supabase access token을 넣어 주세요.`);
  }
  return token;
}

function readJwtPayload(token) {
  try {
    const payload = token.split('.')[1];
    const json = Buffer.from(payload, 'base64url').toString('utf8');
    const data = JSON.parse(json);
    if (typeof data.sub !== 'string' || !data.sub) throw new Error();
    return data;
  } catch {
    throw new Error('공격 점검 토큰의 JWT payload를 읽을 수 없습니다.');
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let body = null;
  try {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      body = await response.json();
    }
  } catch {
    body = null;
  }

  return { response, body };
}

export async function runAttackChecks(config) {
  if (config.step !== 4) {
    throw new Error('이 단계의 공격 점검은 src/attack-check.mjs에 구현해 주세요.');
  }

  const app = getAppUrl(config);

  const results = [];
  const options = {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  };

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

  const aToken = requireToken('ATTACK_A_TOKEN');
  const bToken = requireToken('ATTACK_B_TOKEN');

  const aPayload = readJwtPayload(aToken);
  const bPayload = readJwtPayload(bToken);

  if (aPayload.sub === bPayload.sub) {
    throw new Error('ATTACK_A_TOKEN과 ATTACK_B_TOKEN은 서로 다른 사용자여야 합니다.');
  }

  const notesUrl = new URL('/api/notes', app);
  const bCreate = await requestJson(notesUrl, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${bToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      title: 'STAGE4_ATTACK_B_NOTE',
      body: '소유권 공격 점검용 임시 메모',
    }),
  });

  if (bCreate.response.status !== 201 || typeof bCreate.body?.id !== 'string') {
    throw new Error(`B 테스트 메모 생성 실패: HTTP${bCreate.response.status}`);
  }

  const bNoteId = bCreate.body.id;

  try {
    const attackUrl = new URL(`/api/notes/${encodeURIComponent(bNoteId)}`, app);

    const getAttack = await requestJson(attackUrl, {
      method: 'GET',
      headers: { authorization: `Bearer ${aToken}` },
    });

    results.push({
      attackId: 'idor_cross_user_get',
      expected: 'A가 B 소유 메모를 GET하면 404 NOTE_NOT_FOUND여야 함',
      observed: getAttack.response.status === 404 && getAttack.body?.error === 'NOTE_NOT_FOUND'
        ? 'A의 B 메모 GET 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
        : `A의 B 메모 GET 요청이 HTTP${getAttack.response.status}로 응답함`,
    });

    const putAttack = await requestJson(attackUrl, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${aToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        title: 'IDOR 수정 시도',
        body: 'A가 B 메모를 수정하려는 공격',
      }),
    });

    results.push({
      attackId: 'idor_cross_user_put',
      expected: 'A가 B 소유 메모를 PUT하면 404 NOTE_NOT_FOUND여야 함',
      observed: putAttack.response.status === 404 && putAttack.body?.error === 'NOTE_NOT_FOUND'
        ? 'A의 B 메모 PUT 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
        : `A의 B 메모 PUT 요청이 HTTP${putAttack.response.status}로 응답함`,
    });

    const deleteAttack = await requestJson(attackUrl, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${aToken}` },
    });

    results.push({
      attackId: 'idor_cross_user_delete',
      expected: 'A가 B 소유 메모를 DELETE하면 404 NOTE_NOT_FOUND여야 함',
      observed: deleteAttack.response.status === 404 && deleteAttack.body?.error === 'NOTE_NOT_FOUND'
        ? 'A의 B 메모 DELETE 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
        : `A의 B 메모 DELETE 요청이 HTTP${deleteAttack.response.status}로 응답함`,
    });
  } finally {
    await requestJson(attackUrl, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${bToken}` },
    });
  }

  const forgedCreate = await requestJson(notesUrl, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${aToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      title: 'STAGE4_OWNER_FORGE_TEST',
      body: 'owner_id 위조 점검용 임시 메모',
      owner_id: bPayload.sub,
    }),
  });

  if (forgedCreate.response.status !== 201 || typeof forgedCreate.body?.id !== 'string') {
    throw new Error(`소유자 위조 POST 생성 실패: HTTP${forgedCreate.response.status}`);
  }

  const forgedId = forgedCreate.body.id;

  try {
    const forgedUrl = new URL(`/api/notes/${encodeURIComponent(forgedId)}`, app);

    const bRead = await requestJson(forgedUrl, {
      method: 'GET',
      headers: { authorization: `Bearer ${bToken}` },
    });

    results.push({
      attackId: 'owner_id_forgery_on_create',
      expected: 'A의 POST에 B owner_id를 넣어도 B는 생성 메모를 읽을 수 없어야 함',
      observed: bRead.response.status === 404 && bRead.body?.error === 'NOTE_NOT_FOUND'
        ? 'owner_id 위조가 무시되고 메모가 A 소유로 생성됨'
        : `B의 위조 생성 메모 GET 요청이 HTTP${bRead.response.status}로 응답함`,
    });
  } finally {
    await requestJson(forgedUrl, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${aToken}` },
    });
  }

  return results;
}