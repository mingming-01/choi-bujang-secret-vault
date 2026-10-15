// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// docs/DECIDER_REQUEST.md 계약에 있는 deviceRegistered, stepUp, recentEvents, signals만 읽습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

// 제공 연습 요청(scripts/fixture-7.mjs)이 쓰는 값 이름입니다.
//   signals: { source: 'judge_fixture', network: 'usual' | 'unusual', hour: 0~23 }
//   recentEvents: [{ kind: 'risk_signal', ageSeconds, count }]
// 아래 기준값은 공식 계약이 정하지 않은 가정입니다. 심판 결과와 대조해 조정합니다.
const LATE_HOUR_MAX = 5;                  // 0~5시를 평소와 다른 시각으로 본다.
const RISK_EVENT_MIN_COUNT = 20;          // 연습 요청의 count 값(20)에 맞춘 가정
const RISK_EVENT_MAX_AGE_SECONDS = 600;   // 최근 10분 이내 사건만 본다.
const STEP_UP_MAX_AUTH_AGE_SECONDS = 900; // 계약: 확인된 stepUp 나이는 0~900초

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const inRange = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;

function response(requestId, decision, reasonCode, ruleIds) {
  return { schema: 'aleph.decision.v1', requestId, decision, reasonCode, ruleIds };
}

// 시각·네트워크·다량 읽기 세 가지가 함께 있을 때만 참입니다. 지역 값은 보지 않습니다.
// 출처가 judge_fixture가 아닌 신호는 근거로 쓰지 않으며, 빠진 값을 정상값으로 채우지도 않습니다.
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
    requestId = request.requestId;
    if (request.deviceRegistered !== true) {
      return response(requestId, 'deny', 'device_not_registered', ['device_registered']);
    }
    if (!isCompositeAnomaly(request)) {
      return response(requestId, 'allow', 'approved', ['device_registered']);
    }
    if (isStepUpVerified(request.stepUp)) {
      return response(requestId, 'allow', 'approved', ['device_registered', 'step_up_required']);
    }
    return response(requestId, 'step_up', 'step_up_required', ['step_up_required']);
  } catch {
    // 형식이 깨진 입력(null, getter 오류 등)은 허용하지 않고 계약 형식으로 거부한다.
    return response(requestId, 'deny', 'device_not_registered', ['device_registered']);
  }
}
