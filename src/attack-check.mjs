function getAppUrl(config) {
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

  return app;
}

function requireToken(name) {
  const token = process.env[name];

  if (
    !token ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token)
  ) {
    throw new Error(`${name} 환경변수에 유효한 Supabase access token을 넣어 주세요.`);
  }

  return token;
}

function readJwtPayload(token) {
  try {
    const payload = token.split('.')[1];
    const json = Buffer.from(payload, 'base64url').toString('utf8');
    const data = JSON.parse(json);

    if (typeof data.sub !== 'string' || !data.sub) {
      throw new Error();
    }

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
  if (config.step !== 4 && config.step !== 5) {
    throw new Error('이 단계의 공격 점검은 src/attack-check.mjs에 구현해 주세요.');
  }

  const app = getAppUrl(config);
  const results = [];

  const options = {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  };

  // 1. 홈페이지 보안 헤더 확인
  const homepage = await fetch(new URL('/', app), options);
  const homepageHtml = await homepage.text();

  results.push({
    attackId: 'homepage_nosniff_header',
    expected: '첫 화면 응답에 X-Content-Type-Options: nosniff가 있어야 함',
    observed:
      homepage.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
        ? `첫 화면 HTTP${homepage.status}에서 nosniff 헤더를 확인함`
        : `첫 화면 HTTP${homepage.status}에서 nosniff 헤더를 확인하지 못함`,
  });

  // 2. 정적 data.json 접근 차단 확인
  const dataResponse = await fetch(new URL('/data.json', app), options);

  results.push({
    attackId: 'anonymous_static_note_read',
    expected: '정적 /data.json은 배포되지 않아야 함',
    observed:
      dataResponse.status === 404
        ? '비로그인 요청에서 /data.json이 404로 응답함'
        : `/data.json이 HTTP${dataResponse.status}로 응답함`,
  });

  // 3. 비로그인 API 접근 차단 확인
  const apiResponse = await fetch(new URL('/api/notes', app), options);

  let jsonError = false;

  try {
    const contentType = apiResponse.headers.get('content-type') || '';
    const data = contentType.includes('application/json')
      ? await apiResponse.json()
      : null;

    jsonError = typeof data?.error === 'string';
  } catch {
    // JSON이 아닌 응답은 비로그인 JSON 거부로 세지 않음
  }

  results.push({
    attackId: 'anonymous_api_note_read',
    expected: '비로그인 /api/notes 요청은 HTTP 401/403 및 JSON 오류로 차단되어야 함',
    observed:
      (apiResponse.status === 401 || apiResponse.status === 403) && jsonError
        ? `비로그인 요청이 HTTP${apiResponse.status} JSON 오류로 차단됨`
        : `비로그인 요청 HTTP${apiResponse.status}; JSON 오류 응답=${jsonError}`,
  });

  // 4. 배포 식별 정보 확인
  const identityResponse = await fetch(new URL('/aleph.json', app), options);

  results.push({
    attackId: 'deployment_identity_available',
    expected: '/aleph.json을 계속 제공해야 함',
    observed: identityResponse.ok
      ? `/aleph.json이 HTTP${identityResponse.status}로 제공됨`
      : `/aleph.json이 HTTP${identityResponse.status}로 제공되지 않음`,
  });

  if (config.step === 5) {
    // 5단계: 브라우저가 DB 자료 API를 직접 호출하지 않고 서버 경로를 사용
    const directDataCall = /\.from\s*\(/iu.test(homepageHtml)
      || /\/rest\/v1\//iu.test(homepageHtml);
    const serverNotesPathPresent = /\/api\/notes/iu.test(homepageHtml);

    results.push({
      attackId: 'browser_notes_use_server_api',
      expected: '브라우저 메모 CRUD는 /api/notes를 사용하고 Supabase Data API/DB를 직접 호출하지 않아야 함',
      observed:
        !directDataCall && serverNotesPathPresent
          ? '공개 화면에서 /api/notes 호출을 확인했고 직접 Data API 호출 패턴은 발견되지 않음'
          : `서버 메모 경로=${serverNotesPathPresent}; 직접 DB/Data API 호출 패턴=${directDataCall}`,
    });

    // 공개 키를 원본 자료 경로에 사용해도 자료가 노출되지 않아야 함
    let originalApiUrl;
    try {
      originalApiUrl = new URL(config.originalApiUrl);
    } catch {
      throw new Error('aleph.config.json의 originalApiUrl에 원본 자료 HTTPS 경로가 필요합니다.');
    }
    if (originalApiUrl.protocol !== 'https:' || originalApiUrl.username
        || originalApiUrl.password || originalApiUrl.search || originalApiUrl.hash) {
      throw new Error('aleph.config.json의 originalApiUrl은 쿼리 없는 HTTPS 경로여야 합니다.');
    }

    const publishableKeyMatch = homepageHtml.match(
      /SUPABASE_(?:PUBLISHABLE|ANON)_KEY\s*=\s*['"]([^'"]+)['"]/u
    );
    const publishableKey = publishableKeyMatch?.[1];
    if (!publishableKey) {
      results.push({
        attackId: 'anonymous_original_note_read',
        expected: '공개 anon/publishable 키를 사용한 원본 자료 직접 GET은 거부되어야 함',
        observed: '공개 화면에서 Supabase Auth용 anon/publishable 키를 찾지 못해 원본 경로 접근을 시도하지 않음',
      });
    } else {
      const originalResponse = await requestJson(originalApiUrl, {
        method: 'GET',
        headers: {
          apikey: publishableKey,
          authorization: `Bearer ${publishableKey}`,
        },
      });
      const denied = (originalResponse.response.status === 401
          || originalResponse.response.status === 403)
        && typeof originalResponse.body?.error === 'string';

      results.push({
        attackId: 'anonymous_original_note_read',
        expected: '공개 anon/publishable 키를 사용한 원본 자료 직접 GET은 HTTP 401/403 JSON으로 거부되어야 함',
        observed: denied
          ? `공개 키를 이용한 originalApiUrl GET이 HTTP${originalResponse.response.status} JSON 오류로 거부됨`
          : `originalApiUrl GET이 HTTP${originalResponse.response.status}로 응답함; JSON 오류=${typeof originalResponse.body?.error === 'string'}`,
      });
    }
  }

  // 실제 A/B 사용자 토큰
  const aToken = requireToken('ATTACK_A_TOKEN');
  const bToken = requireToken('ATTACK_B_TOKEN');

  const aPayload = readJwtPayload(aToken);
  const bPayload = readJwtPayload(bToken);

  if (aPayload.sub === bPayload.sub) {
    throw new Error(
      'ATTACK_A_TOKEN과 ATTACK_B_TOKEN은 서로 다른 사용자여야 합니다.'
    );
  }

  const notesUrl = new URL('/api/notes', app);

  if (config.step === 5) {
    // A가 자기 자료를 서버 API에서 정상적으로 읽을 수 있어야 함
    const aCreate = await requestJson(notesUrl, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${aToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        title: 'STAGE5_ATTACK_A_READ_TEST',
        body: '자기 메모 서버 조회 경로 점검용 임시 메모',
      }),
    });

    if (aCreate.response.status !== 201 || typeof aCreate.body?.id !== 'string') {
      throw new Error(`A 테스트 메모 생성 실패: HTTP${aCreate.response.status}`);
    }

    const aNoteUrl = new URL(`/api/notes/${encodeURIComponent(aCreate.body.id)}`, app);
    try {
      const aRead = await requestJson(aNoteUrl, {
        method: 'GET',
        headers: { authorization: `Bearer ${aToken}` },
      });

      results.push({
        attackId: 'owner_can_read_own_note_via_server_api',
        expected: 'A가 자신의 메모를 GET /api/notes/:id로 조회하면 HTTP 200과 같은 메모가 반환되어야 함',
        observed:
          aRead.response.status === 200
            && aRead.body?.id === aCreate.body.id
            && aRead.body?.title === 'STAGE5_ATTACK_A_READ_TEST'
            ? 'A가 /api/notes/:id에서 자신의 메모를 정상 조회함'
            : `A 자신의 메모 조회가 HTTP${aRead.response.status}로 응답함`,
      });
    } finally {
      await requestJson(aNoteUrl, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${aToken}` },
      });
    }
  }

  // 5. B가 자신의 임시 메모 생성
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

  if (
    bCreate.response.status !== 201 ||
    typeof bCreate.body?.id !== 'string'
  ) {
    throw new Error(
      `B 테스트 메모 생성 실패: HTTP${bCreate.response.status}`
    );
  }

  const bNoteId = bCreate.body.id;
  let attackUrl;

  try {
    attackUrl = new URL(
      `/api/notes/${encodeURIComponent(bNoteId)}`,
      app
    );

    // 6. A가 B의 메모를 조회하는 IDOR 공격
    const getAttack = await requestJson(attackUrl, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${aToken}`,
      },
    });

    results.push({
      attackId: 'idor_cross_user_get',
      expected: 'A가 B 소유 메모를 GET하면 404 NOTE_NOT_FOUND여야 함',
      observed:
        getAttack.response.status === 404 &&
        getAttack.body?.error === 'NOTE_NOT_FOUND'
          ? 'A의 B 메모 GET 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
          : `A의 B 메모 GET 요청이 HTTP${getAttack.response.status}로 응답함`,
    });

    // 7. A가 B의 메모를 수정하는 IDOR 공격
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
      observed:
        putAttack.response.status === 404 &&
        putAttack.body?.error === 'NOTE_NOT_FOUND'
          ? 'A의 B 메모 PUT 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
          : `A의 B 메모 PUT 요청이 HTTP${putAttack.response.status}로 응답함`,
    });

    // 8. A가 B의 메모를 삭제하는 IDOR 공격
    const deleteAttack = await requestJson(attackUrl, {
      method: 'DELETE',
      headers: {
        authorization: `Bearer ${aToken}`,
      },
    });

    results.push({
      attackId: 'idor_cross_user_delete',
      expected: 'A가 B 소유 메모를 DELETE하면 404 NOTE_NOT_FOUND여야 함',
      observed:
        deleteAttack.response.status === 404 &&
        deleteAttack.body?.error === 'NOTE_NOT_FOUND'
          ? 'A의 B 메모 DELETE 요청이 HTTP404 NOTE_NOT_FOUND로 차단됨'
          : `A의 B 메모 DELETE 요청이 HTTP${deleteAttack.response.status}로 응답함`,
    });
  } finally {
    // B가 만든 테스트 메모 정리
    if (attackUrl) {
      await requestJson(attackUrl, {
        method: 'DELETE',
        headers: {
          authorization: `Bearer ${bToken}`,
        },
      });
    }
  }

  // 9. A가 owner_id를 B로 위조하여 메모 생성
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

  if (
    forgedCreate.response.status !== 201 ||
    typeof forgedCreate.body?.id !== 'string'
  ) {
    throw new Error(
      `소유자 위조 POST 생성 실패: HTTP${forgedCreate.response.status}`
    );
  }

  const forgedId = forgedCreate.body.id;
  let forgedUrl;

  try {
    forgedUrl = new URL(
      `/api/notes/${encodeURIComponent(forgedId)}`,
      app
    );

    // 10. B가 owner_id 위조 메모를 읽을 수 있는지 확인
    const bRead = await requestJson(forgedUrl, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${bToken}`,
      },
    });

    results.push({
      attackId: 'owner_id_forgery_on_create',
      expected: 'A의 POST에 B owner_id를 넣어도 B는 생성 메모를 읽을 수 없어야 함',
      observed:
        bRead.response.status === 404 &&
        bRead.body?.error === 'NOTE_NOT_FOUND'
          ? 'owner_id 위조가 무시되고 메모가 A 소유로 생성됨'
          : `B의 위조 생성 메모 GET 요청이 HTTP${bRead.response.status}로 응답함`,
    });
  } finally {
    // A가 만든 위조 테스트 메모 정리
    if (forgedUrl) {
      await requestJson(forgedUrl, {
        method: 'DELETE',
        headers: {
          authorization: `Bearer ${aToken}`,
        },
      });
    }
  }

  return results;
}
