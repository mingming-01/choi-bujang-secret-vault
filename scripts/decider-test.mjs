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
      || !ruleIds.includes('device_registered')
      || !ruleIds.includes('composite_access_anomaly')) {
    throw new Error('device_registered 및 composite_access_anomaly 규칙을 RULE_IDS에 구현해 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const withNewId = request => ({ ...request, requestId: randomUUID() });
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow',
      reasonCode: 'approved', ruleIds: ['device_registered'] },
    { name: '복합 이상 접속은 추가 확인', request: suspicious, decision: 'step_up',
      reasonCode: 'composite_anomaly_step_up', ruleIds: ['composite_access_anomaly'] },
    { name: '지역 신호만으로 이상 판정하지 않음', request: withNewId({ ...normal,
      signals: { ...normal.signals, region: 'foreign' },
    }), decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] },
    { name: '대량 조회와 첫 네트워크만으로 추가 확인하지 않음', request: withNewId({
      ...normal,
      signals: { ...normal.signals, network: 'first_seen' },
      recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }],
    }), decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] },
    { name: '늦은 시각과 대량 조회만으로 추가 확인하지 않음', request: withNewId({
      ...normal,
      signals: { ...normal.signals, hour: 3 },
      recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }],
    }), decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] },
    { name: '출처가 없는 신호와 대량 조회만으로 추가 확인하지 않음', request: withNewId({
      ...normal,
      signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 },
      recentEvents: [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }],
    }), decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] },
    { name: '불명확한 출처의 복합 주장도 거부하고 step_up 근거로 쓰지 않음', request: withNewId({
      ...suspicious,
      signals: { ...suspicious.signals, source: 'client' },
    }), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '미등록 기기의 가상 요청', request: withNewId({ ...normal,
      deviceRegistered: false }), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '등록 여부가 누락된 요청', request: (() => {
      const { deviceRegistered, ...request } = normal;
      return withNewId(request);
    })(), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '필수 접속 정보가 누락된 요청', request: (() => {
      const { signals, ...request } = normal;
      return withNewId(request);
    })(), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '시각 신호가 누락된 요청', request: withNewId({ ...normal,
      signals: (({ hour, ...signals }) => signals)(normal.signals),
    }), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '행동 사건 목록이 누락된 요청', request: (() => {
      const { recentEvents, ...request } = normal;
      return withNewId(request);
    })(), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '클라이언트 임의 헤더가 추가된 요청', request: withNewId({
      ...normal, headers: { 'x-forwarded-for': '192.0.2.1' },
    }), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
    { name: '미확인 출처에서 지역·네트워크를 주장한 요청', request: withNewId({
      ...normal,
      signals: { ...normal.signals, source: 'none', region: 'foreign', network: 'unusual' },
    }), decision: 'deny', reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'] },
  ];
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && response.reasonCode === item.reasonCode
      && JSON.stringify(response.ruleIds) === JSON.stringify(item.ruleIds);
    results.push({ name: item.name, passed: valid });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
