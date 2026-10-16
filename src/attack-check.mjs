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

async function runLocalDeviceRegistrationChecks() {
  const { decide, RULE_IDS } = await import('./decider.mjs');
  if (typeof decide !== 'function' || !Array.isArray(RULE_IDS)
      || !RULE_IDS.includes('device_registered')) {
    throw new Error('6단계 로컬 점검에 필요한 device_registered 판정 규칙을 확인할 수 없습니다.');
  }

  const checks = [
    {
      attackId: 'device_registered_allow',
      expected: 'deviceRegistered=true인 로컬 가상 요청은 allow',
      request: { requestId: 'local-step6-registered', deviceRegistered: true },
      decision: 'allow',
      reasonCode: 'approved',
    },
    {
      attackId: 'device_not_registered_deny',
      expected: 'deviceRegistered=false인 로컬 가상 요청은 deny 및 device_not_registered',
      request: { requestId: 'local-step6-unregistered', deviceRegistered: false },
      decision: 'deny',
      reasonCode: 'device_not_registered',
    },
    {
      attackId: 'device_registration_missing_deny',
      expected: 'deviceRegistered가 누락된 로컬 가상 요청은 deny 및 device_not_registered',
      request: { requestId: 'local-step6-missing' },
      decision: 'deny',
      reasonCode: 'device_not_registered',
    },
  ];


  const results = [];

  for (const check of checks) {
    const response = await decide(check.request);
    const validRuleIds = Array.isArray(response?.ruleIds)
      && response.ruleIds.length === 1
      && response.ruleIds[0] === 'device_registered';

    const passed = response?.decision === check.decision
      && response?.reasonCode === check.reasonCode
      && validRuleIds;

    if (!passed) {
      throw new Error(
        `6단계 점검 실패: ${check.attackId} `
        + `(decision=${String(response?.decision)}, `
        + `reasonCode=${String(response?.reasonCode)}, `
        + `ruleIds=${JSON.stringify(response?.ruleIds)})`
      );
    }

    results.push({
      attackId: check.attackId,
      expected: check.expected,
      observed: `로컬 가상 요청 검증: 기대 결과와 일치 (decision=${response.decision}, reasonCode=${response.reasonCode})`,
    });
  }

  return results;

}

async function runLocalStep7Checks() {
  // 6단계 기기 등록 점검을 그대로 유지하고 7단계 가상 접속 점검을 더합니다.
  const results = await runLocalDeviceRegistrationChecks();
  const { decide, RULE_IDS } = await import('./decider.mjs');
  if (!Array.isArray(RULE_IDS) || !RULE_IDS.includes('step_up_required')) {
    throw new Error('7단계 로컬 점검에 필요한 step_up_required 판정 규칙을 확인할 수 없습니다.');
  }
  const { randomUUID } = await import('node:crypto');
  const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
  const { normal, suspicious } = fixtureRequests();
  const variant = (base, patch) => ({ ...base, requestId: randomUUID(), ...patch });

  const checks = [
    {
      attackId: 'normal_access_allow',
      expected: '평소와 같은 로컬 가상 접속은 allow',
      request: normal, decision: 'allow', reasonCode: 'approved',
    },
    {
      attackId: 'composite_anomaly_step_up',
      expected: '평소와 다른 시각·네트워크와 다량 읽기가 함께인 로컬 가상 접속은 step_up 및 step_up_required',
      request: suspicious, decision: 'step_up', reasonCode: 'step_up_required',
    },
    {
      attackId: 'composite_anomaly_rechecked_allow',
      expected: '다시 확인을 마친 복합 이상 로컬 가상 접속은 allow',
      request: variant(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } }),
      decision: 'allow', reasonCode: 'approved',
    },
    {
      attackId: 'region_only_change_allow',
      expected: '지역만 달라진 로컬 가상 접속은 영구 차단하지 않고 allow',
      request: variant(normal, { signals: { ...normal.signals, region: 'foreign' } }),
      decision: 'allow', reasonCode: 'approved',
    },
    {
      attackId: 'partial_anomaly_allow',
      expected: '시각·네트워크·다량 읽기 중 둘만 있는 로컬 가상 접속은 allow',
      request: variant(suspicious, { recentEvents: [] }),
      decision: 'allow', reasonCode: 'approved',
    },
    {
      attackId: 'unverified_signal_source_not_trusted',
      expected: '출처가 judge_fixture가 아닌 신호는 근거로 쓰지 않아 step_up이 되지 않음',
      request: variant(suspicious, { signals: { ...suspicious.signals, source: 'none' } }),
      decision: 'allow', reasonCode: 'approved',
    },
    {
      attackId: 'unregistered_device_with_anomaly_deny',
      expected: '미등록 기기의 복합 이상 로컬 가상 접속은 deny 및 device_not_registered',
      request: variant(suspicious, { deviceRegistered: false }),
      decision: 'deny', reasonCode: 'device_not_registered',
    },
  ];

  for (const check of checks) {
    const response = await decide(check.request);
    const validShape = response && typeof response === 'object'
      && Object.keys(response).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
      && response.requestId === check.request.requestId
      && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
      && response.ruleIds.every(id => RULE_IDS.includes(id));
    const passed = validShape && response.decision === check.decision
      && response.reasonCode === check.reasonCode;
    if (!passed) {
      throw new Error('7단계 점검 실패: ' + check.attackId
        + ' (decision=' + String(response?.decision)
        + ', reasonCode=' + String(response?.reasonCode) + ')');
    }
    results.push({
      attackId: check.attackId,
      expected: check.expected,
      observed: '로컬 가상 요청 검증: 기대 결과와 일치 (decision=' + response.decision
        + ', reasonCode=' + response.reasonCode + ')',
    });
  }

  results.push({
    attackId: 'relogin_gate_not_run',
    expected: '다시 로그인 전 자료 차단과 새 로그인 뒤 재판정은 제공 엔진이 연결된 환경에서만 시험할 수 있음',
    observed: '미실행: 이번 로컬 점검은 판정기 응답만 확인했고 실제 자료 차단과 재로그인 뒤 재판정은 시험하지 않았음',
  });

  return results;
}

async function runLocalStep8Checks() {
  const { checkDecider } = await import('../scripts/decider-test.mjs');
  const { decide, RULE_IDS } = await import('./decider.mjs');

  const checks = await checkDecider({ decide, ruleIds: RULE_IDS });
  const failed = checks.find(item => !item.passed);

  if (failed) {
    throw new Error(`8단계 자원 정책 점검 실패: ${failed.name}`);
  }

  return checks.slice(-16).map((item, index) => ({
    attackId: `step8_local_${index + 1}`,
    expected: `${item.name}에 대한 판정이 과제의 허용·거부 조건과 일치해야 함`,
    observed: `로컬 가상 요청 점검 통과: ${item.name}`,
  }));
}

async function runLocalStep9Checks() {
  const { detect } = await import('./detect.mjs');
  const { checkDetection } = await import('../scripts/detect-test.mjs');

  const checks = await checkDetection(detect);
  const failed = checks.find(item => !item.passed);

  if (failed) {
    throw new Error(`9단계 비정상 조회 점검 실패: ${failed.name}`);
  }

  return checks.map((item, index) => ({
    attackId: `step9_detection_${index + 1}`,
    expected: `${item.name} 조건에서 탐지 결과가 기대값과 일치해야 함`,
    observed: `로컬 가상 사건 점검 통과: ${item.name}`,
  }));
}

async function runLocalStep10Checks() {
  const {
    loadVerifiedPolicyFixture,
    loadVerifiedCurrentPolicyFixture,
    compareFixturePolicies,
    fixtureReadAllowed,
    restoreFixturePolicies,
    loadVerifiedMemoFixture,
    loadVerifiedMemoCurrentFixture,
    restoreFixtureMemo,
  } = await import('./recovery.mjs');

  const results = [];

  const safeSnapshot = await loadVerifiedPolicyFixture();
  const currentSnapshot = await loadVerifiedCurrentPolicyFixture();
  const policyIds = [
    'note.read.owner',
    'note.read.cross-user',
  ];

  const comparison = compareFixturePolicies({
    safeSnapshot,
    currentSnapshot,
    policyIds,
  });

  const restored = restoreFixturePolicies({
    safeSnapshot,
    currentSnapshot,
    policyIds,
    confirmation: comparison.confirmation,
  });

  const ownerAllowed = fixtureReadAllowed({
    policySnapshot: restored,
    requesterId: 'fixture-owner-b',
    ownerId: 'fixture-owner-b',
  });

  const crossUserDenied = !fixtureReadAllowed({
    policySnapshot: restored,
    requesterId: 'another-user',
    ownerId: 'fixture-owner-b',
  });

  if (!ownerAllowed || !crossUserDenied) {
    throw new Error('10단계 정책 복구 접근 점검 실패');
  }

  results.push({
    attackId: 'step10_policy_restore_access',
    expected: '소유자 접근은 허용하고 다른 사용자의 접근은 거부',
    observed: '로컬 훈련용 정책 fixture에서 복구 후 접근 판정 확인',
  });

  const backup = await loadVerifiedMemoFixture();
  const currentStore = await loadVerifiedMemoCurrentFixture();
  const target = {
    id: backup.id,
    ownerId: backup.ownerId,
    contentSha256: backup.contentSha256,
  };

  const restoredStore = restoreFixtureMemo({
    backup,
    currentStore,
    target,
    confirmation:
      `RESTORE ${backup.id} ${backup.ownerId} ${backup.contentSha256}`,
  });

  const restoredMemo = restoredStore.memos.find(
    memo => memo.id === backup.id,
  );

  if (!restoredMemo
      || restoredMemo.ownerId !== backup.ownerId
      || restoredMemo.body !== backup.body
      || JSON.stringify(restoredStore.auditEvents)
        !== JSON.stringify(currentStore.auditEvents)) {
    throw new Error('10단계 메모 복구 보존 점검 실패');
  }

  results.push({
    attackId: 'step10_memo_restore_preservation',
    expected: '지정한 메모를 복구하고 기존 감사 기록을 보존',
    observed: '로컬 훈련용 메모 fixture에서 복구 및 감사 기록 보존 확인',
  });

  results.push({
    attackId: 'step10_production_restore_not_verified',
    expected: '실제 Supabase 정책과 메모 복구 여부를 별도로 확인',
    observed: '미검증: 로컬 훈련용 fixture만 점검했으며 실제 Supabase 데이터는 변경하지 않음',
  });

  return results;
}

async function runLocalStep11Checks() {
  const { execFileSync } = await import('node:child_process');

  try {
    execFileSync(
      process.execPath,
      ['--test', 'test/device-approval.test.mjs'],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
        stdio: 'pipe',
      },
    );
  } catch (error) {
    const output = [error.stdout, error.stderr]
      .filter(Boolean)
      .join('\n');

    throw new Error(
      `11단계 기기 서명 점검 실패:\n${output || error.message}`,
    );
  }

  return [
    {
      attackId: 'step11_missing_device_signature',
      expected: '기기 서명 헤더가 없는 보호 요청 거부',
      observed: '로컬 기기 승인 테스트 통과',
    },
    {
      attackId: 'step11_signed_path_tampering',
      expected: '서명 후 요청 경로가 변경된 요청 거부',
      observed: '로컬 경로 변조 테스트 통과',
    },
    {
      attackId: 'step11_signed_body_tampering',
      expected: '서명 후 요청 본문이 변경된 요청 거부',
      observed: '로컬 본문 변조 테스트 통과',
    },
  ];
}


async function runStep12ApiChecks(config) {
  const app = getAppUrl(config);
  const checks = [
    {
      attackId: 'step12_unauth_war_room',
      expected: '인증 없는 GET /api/war-room은 401 또는 403으로 거부',
      method: 'GET',
      path: '/api/war-room',
    },
    {
      attackId: 'step12_unauth_notes',
      expected: '인증 없는 GET /api/notes는 401 또는 403으로 거부',
      method: 'GET',
      path: '/api/notes',
    },
    {
      attackId: 'step12_unauth_restore',
      expected: '유효한 복구 미리보기 본문이어도 인증 없는 POST /api/restore는 401 또는 403으로 거부',
      method: 'POST',
      path: '/api/restore',
      body: {
        id: '1',
        ownerId: '11111111-1111-4111-8111-111111111111',
        contentSha256: 'a'.repeat(64),
      },
    },
  ];

  const results = [];

  for (const check of checks) {
    const checkedAt = new Date().toISOString();

    try {
      const options = { method: check.method };

      if (check.body !== undefined) {
        options.headers = { 'content-type': 'application/json' };
        options.body = JSON.stringify(check.body);
      }

      const { response, body } = await requestJson(
        new URL(check.path, app),
        options,
      );

      const denied = response.status === 401 || response.status === 403;
      const errorCode = typeof body?.error === 'string'
        && /^[A-Z0-9_.-]{1,80}$/iu.test(body.error)
        ? body.error
        : 'not_provided';
      const rawRequestId = response.headers.get('x-request-id')
        || response.headers.get('x-vercel-id')
        || body?.requestId;
      const requestId = typeof rawRequestId === 'string'
        && rawRequestId.length <= 100
        ? rawRequestId
        : 'not_provided';

      results.push({
        attackId: check.attackId,
        expected: check.expected,
        observed: `${denied ? '기대 상태와 일치' : '기대 상태와 불일치'}: `
          + `HTTP${response.status}; error=${errorCode}; `
          + `requestId=${requestId}; checkedAt=${checkedAt}`,
      });
    } catch (error) {
      results.push({
        attackId: check.attackId,
        expected: check.expected,
        observed: `미검증: HTTP 응답 없음; checkedAt=${checkedAt}; `
          + `cause=${error?.name || 'RequestError'}`,
      });
    }
  }

  return results;
}

export async function runAttackChecks(config) {
  if (config.step === 12) {
    return runStep12ApiChecks(config);
  }
  if (config.step === 11) {
    return runLocalStep11Checks();
  }
  if (config.step === 10) {
    return runLocalStep10Checks();
  }
  if (config.step === 9) {
    return runLocalStep9Checks();
  }
  if (config.step === 7) {
    return runLocalStep7Checks();
  }

  if (config.step === 6) {
    return runLocalDeviceRegistrationChecks();
  }

  if (config.step !== 4 && config.step !== 5 && config.step !== 8) {
    throw new Error('이 단계의 공격 점검은 src/attack-check.mjs에 구현해 주세요.');
  }

  if (config.step === 8) {
    return runLocalStep8Checks();
  }
  const app = getAppUrl(config);
  const results = config.step === 8
    ? await runLocalStep8Checks()
    : [];

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

  // A가 자기 자료를 서버 API에서 정상적으로 읽을 수 있어야 함
    if (config.step === 5 || config.step === 8) {
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
