import { resourceAccessAllowed } from './resources.mjs';
// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// docs/DECIDER_REQUEST.md 계약에 있는 요청 최상위 필드만 읽습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone_access',
]);
// 제공 연습 요청(scripts/fixture-7.mjs)이 쓰는 값 이름입니다.
//   signals: { source: 'judge_fixture', network: 'usual' | 'unusual', hour: 0~23 }
//   recentEvents: [{ kind: 'risk_signal', ageSeconds, count }]
// 아래 기준값은 공식 계약이 정하지 않은 가정입니다. 심판 결과와 대조합니다.
const LATE_HOUR_MAX = 5;
const RISK_EVENT_MIN_COUNT = 20;
const RISK_EVENT_MAX_AGE_SECONDS = 600;
const STEP_UP_MAX_AUTH_AGE_SECONDS = 900;

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const inRange = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;

function response(requestId, decision, reasonCode, ruleIds) {
  return { schema: 'aleph.decision.v1', requestId, decision, reasonCode, ruleIds };
}

function isCompositeAnomaly(request) {
  const { signals, recentEvents } = request;
  if (!isObject(signals) || signals.source !== 'judge_fixture') return false;
  const unusualHour = inRange(signals.hour, 0, LATE_HOUR_MAX);
  const unusualNetwork = signals.network === 'unusual';
  const heavyRead = Array.isArray(recentEvents) && recentEvents.length <= 12
    && recentEvents.some(event => isObject(event)
      && event.kind === 'risk_signal'
      && inRange(event.ageSeconds, 0, RISK_EVENT_MAX_AGE_SECONDS)
      && Number.isInteger(event.count) && event.count >= RISK_EVENT_MIN_COUNT);
  return unusualHour && unusualNetwork && heavyRead;
}

function isStepUpVerified(stepUp) {
  return isObject(stepUp) && stepUp.verified === true
    && inRange(stepUp.authAgeSeconds, 0, STEP_UP_MAX_AUTH_AGE_SECONDS);
}

export async function decide(request) {
  let requestId;
  try {
    if (!isObject(request)) throw new TypeError('invalid_request');
    const allowedFields = new Set([
      'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
      'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
      'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
    ]);
    if (Object.keys(request).some(key => !allowedFields.has(key))) {
      throw new TypeError('unexpected_request_field');
    }
    requestId = request.requestId;
    if (request.deviceRegistered !== true) {
      return response(requestId, 'deny', 'device_not_registered', ['device_registered']);
    }
    if (!resourceAccessAllowed(request)) {
      return response(requestId, 'deny', 'device_not_registered', ['resource_zone_access']);
    }
    if (!isCompositeAnomaly(request)) {
      return response(requestId, 'allow', 'approved', ['device_registered']);
    }
    if (isStepUpVerified(request.stepUp)) {
      return response(requestId, 'allow', 'approved', ['device_registered', 'step_up_required']);
    }
    return response(requestId, 'step_up', 'step_up_required', ['step_up_required']);
  } catch {
    return response(requestId, 'deny', 'device_not_registered', ['device_registered']);
  }
}
