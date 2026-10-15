import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }

  const { normal, suspicious } = fixtureRequests();

  const checks = [
    {
      name: '등록 기기의 정상 요청',
      request: normal,
      decision: 'allow',
      reasonCode: 'approved',
    },
    {
      name: '미등록 기기의 가상 요청',
      request: {
        ...normal,
        requestId: randomUUID(),
        deviceRegistered: false,
      },
      decision: 'deny',
      reasonCode: 'device_not_registered',
    },
    {
      name: '등록 여부가 누락된 요청',
      request: (() => {
        const { deviceRegistered, ...request } = normal;
        return { ...request, requestId: randomUUID() };
      })(),
      decision: 'deny',
      reasonCode: 'device_not_registered',
    },
  ];

  if (ruleIds.includes('step_up_required')) {
    checks.push(
      {
        name: '복합 이상 접속',
        request: suspicious,
        decision: 'step_up',
        reasonCode: 'step_up_required',
      },
      {
        name: '다시 확인한 복합 이상 접속',
        request: {
          ...suspicious,
          requestId: randomUUID(),
          stepUp: { verified: true, authAgeSeconds: 60 },
        },
        decision: 'allow',
      },
    );
  }

  // 자원별 경로와 메서드 정책을 확인하는 가상 요청입니다.
  const resourceCases = [
    {
      name: '메모 단건 GET',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/notes/demo',
        route: 'GET /notes/:id',
      },
      decision: 'allow',
    },
    {
      name: '메모 전체 목록 GET',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/notes',
        route: 'GET /notes',
      },
      decision: 'deny',
    },
    {
      name: '메모 생성 POST',
      fields: {
        service: 'notes',
        method: 'POST',
        path: '/notes',
        route: 'POST /notes',
      },
      decision: 'deny',
    },
    {
      name: '메모 단건 PUT',
      fields: {
        service: 'notes',
        method: 'PUT',
        path: '/notes/demo',
        route: 'PUT /notes/:id',
      },
      decision: 'allow',
    },
    {
      name: '메모 단건 DELETE',
      fields: {
        service: 'notes',
        method: 'DELETE',
        path: '/notes/demo',
        route: 'DELETE /notes/:id',
      },
      decision: 'allow',
    },
    {
      name: 'API 접두어가 있는 메모 단건 GET',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/api/notes/demo',
        route: 'GET /api/notes/:id',
      },
      decision: 'allow',
    },
    {
      name: '반 공지 단건 GET',
      fields: {
        service: 'notices',
        method: 'GET',
        path: '/notices/demo',
        route: 'GET /notices/:id',
      },
      decision: 'allow',
    },
    {
      name: '반 공지 목록 GET',
      fields: {
        service: 'notices',
        method: 'GET',
        path: '/notices',
        route: 'GET /notices',
      },
      decision: 'allow',
    },
    ...['POST', 'PUT', 'PATCH', 'DELETE'].map(method => ({
      name: `반 공지 ${method}`,
      fields: {
        service: 'notices',
        method,
        path: '/notices/demo',
        route: `${method} /notices/:id`,
      },
      decision: 'deny',
    })),
    {
      name: '등록되지 않은 강사 자료 경로',
      fields: {
        service: 'instructor-materials',
        method: 'GET',
        path: '/materials/guide',
        route: 'GET /materials/:id',
      },
      decision: 'deny',
    },
    {
      name: '알 수 없는 기능 경로',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/notes/demo/export',
        route: 'GET /notes/:id/export',
      },
      decision: 'deny',
    },
    {
      name: 'export를 메모 ID로 위장',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/notes/export',
        route: 'GET /notes/:id',
      },
      decision: 'deny',
    },
    {
      name: '쿼리로 자원 종류를 바꾸지 않음',
      fields: {
        service: 'notes',
        method: 'GET',
        path: '/notes/demo',
        route: 'GET /notes/:id',
        queryLength: 17,
        querySha256: 'a'.repeat(64),
      },
      decision: 'allow',
    },
  ];

  for (const item of resourceCases) {
    const request = {
      ...normal,
      requestId: randomUUID(),
      ...item.fields,
      deviceRegistered: true,
      signals: {
        source: 'none',
        region: 'unknown',
        network: 'unknown',
        hour: 12,
      },
      recentEvents: [],
      stepUp: { verified: false, authAgeSeconds: null },
    };

    checks.push({
      name: item.name,
      request,
      decision: item.decision,
      requiredRuleId: item.decision === 'deny'
        ? 'resource_zone_access'
        : undefined,
    });
  }

  const results = [];

  for (const item of checks) {
    const response = await decide(item.request);

    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode)
      && (!item.requiredRuleId || response.ruleIds.includes(item.requiredRuleId));

    results.push({
      name: item.name,
      passed: valid,
    });
  }

  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });

    for (const item of results) {
      process.stdout.write(
        `${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`,
      );
    }

    process.stdout.write(
      '이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n',
    );

    if (results.some(item => !item.passed)) {
      process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}