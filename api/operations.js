import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyDeviceRequest } from '../src/device-approval.mjs';
import { RULE_IDS } from '../src/decider.mjs';

const BEARER_TOKEN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function getRuntime() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) throw new Error('service_not_configured');

  const url = new URL(supabaseUrl);
  const issuer = new URL(config.identityProvider.issuer);
  if (url.protocol !== 'https:' || url.origin !== issuer.origin
      || (url.pathname !== '/' && url.pathname !== '') || url.username || url.password) {
    throw new Error('service_not_configured');
  }

  const supabase = createClient(url.origin, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  return {
    supabase,
    verifyLogin: createLoginVerifier({
      config,
      supabaseSecretKey: secretKey,
      supabaseClient: supabase,
    }),
  };
}

const RULE_SUMMARIES = Object.freeze({
  device_registered: '승인된 기기인지 확인',
  step_up_required: '복합 이상 신호가 있으면 추가 확인 요구',
  resource_zone_access: '허용된 자원과 경로인지 확인',
});

function createSnapshot(now, idFactory) {
  const rules = RULE_IDS.map(id => ({
    id,
    summary: RULE_SUMMARIES[id] || '서버 판정기 규칙',
  }));
  const observedAt = now().toISOString();
  const requestRef = `ops-${idFactory().replace(/-/gu, '').slice(0, 12)}`;

  // 이 API는 규칙 구성을 보여 줍니다. 판정·탐지·회수·복구를 실행하지 않습니다.
  // 로그 레코드와 응답의 집계 필드는 같은 값을 공유합니다.
  const record = {
    requestRef,
    recordedAt: observedAt,
    ruleCount: rules.length,
    decisionStatus: 'not_run',
    detectionStatus: 'not_run',
    incidentCount: null,
    incidentRecordCount: null,
    recoveryStatus: 'not_run',
    restoreVersion: null,
  };

  return {
    schema: 'aleph.operations-room.v1',
    observedAt,
    summary: {
      decider: {
        status: 'configured',
        decisionStatus: 'not_run',
        rules,
      },
      detection: {
        status: 'not_run',
        incidentCount: null,
        recordCount: null,
        incidents: [],
      },
      recovery: {
        status: 'not_run',
        restoreRoute: config.restoreRoute,
        restoreVersion: null,
        changedFieldCount: null,
      },
    },
    maskedServerRecords: [record],
  };
}

function getDefaultLogger() {
  return record => console.info(`[operations-room] ${JSON.stringify(record)}`);
}

export function createOperationsHandler({
  runtimeProvider = getRuntime,
  deviceVerifier = verifyDeviceRequest,
  logger = getDefaultLogger(),
  now = () => new Date(),
  idFactory = randomUUID,
} = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store, max-age=0');
    response.setHeader('X-Content-Type-Options', 'nosniff');

    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }

    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string' || !BEARER_TOKEN.test(authorization)) {
      return response.status(401).json({ error: 'AUTHENTICATION_REQUIRED' });
    }

    let runtime;
    let identity;
    try {
      runtime = runtimeProvider();
      identity = await runtime.verifyLogin(authorization);
    } catch {
      return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
    }

    if (!identity || identity.kind !== 'student' || typeof identity.userId !== 'string') {
      return response.status(403).json({ error: 'OPERATIONS_ROOM_NOT_ALLOWED' });
    }

    let deviceCheck;
    try {
      deviceCheck = await deviceVerifier(request, {
        supabase: runtime.supabase,
        userId: identity.userId,
        config,
      });
    } catch {
      return response.status(503).json({ error: 'DEVICE_APPROVAL_UNAVAILABLE' });
    }
    if (!deviceCheck?.ok) {
      return response.status(deviceCheck?.status || 403).json({
        error: deviceCheck?.error || 'DEVICE_NOT_APPROVED',
      });
    }

    const snapshot = createSnapshot(now, idFactory);
    // 메모, 인증값, 사용자 ID, 기기 ID, 요청 본문은 기록하지 않습니다.
    logger(snapshot.maskedServerRecords[0]);
    return response.status(200).json(snapshot);
  };
}

export default createOperationsHandler();
