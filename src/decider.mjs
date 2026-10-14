// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'composite_access_anomaly']);

const REQUEST_KEYS = Object.freeze([
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const RECENT_EVENT_WINDOW_SECONDS = 600;
const BULK_READ_MIN_COUNT = 20;

function isPlainDataObject(value, expectedKeys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;

  const keys = Reflect.ownKeys(value);
  if (keys.length !== expectedKeys.length
      || keys.some(key => typeof key !== 'string' || !expectedKeys.includes(key))) return false;
  return keys.every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function validRecentEvents(events) {
  if (!Array.isArray(events) || events.length > 12
      || Object.keys(events).length !== events.length) return false;
  for (let index = 0; index < events.length; index += 1) {
    if (!Object.hasOwn(events, index)
        || !isPlainDataObject(events[index], ['kind', 'ageSeconds', 'count'])) return false;
    const event = events[index];
    if (typeof event.kind !== 'string' || event.kind.length === 0 || event.kind.length > 80
        || !Number.isSafeInteger(event.ageSeconds) || event.ageSeconds < 0
        || !Number.isSafeInteger(event.count) || event.count < 0) return false;
  }
  return true;
}

function validRequest(request) {
  try {
    if (!isPlainDataObject(request, REQUEST_KEYS)
        || request.schema !== 'aleph.decision.v1'
        || typeof request.requestId !== 'string' || !UUID.test(request.requestId)
        || !['classId', 'projectId', 'subjectId', 'service', 'method', 'path', 'route']
          .every(key => typeof request[key] === 'string'
            && request[key].length > 0 && request[key].length <= 256)
        || typeof request.deviceId !== 'string' || !/^[0-9a-f]{16}$/u.test(request.deviceId)
        || !Number.isSafeInteger(request.queryLength) || request.queryLength < 0
        || typeof request.querySha256 !== 'string' || !SHA256.test(request.querySha256)
        || typeof request.at !== 'string' || !Number.isFinite(Date.parse(request.at))
        || new Date(request.at).toISOString() !== request.at
        || Math.abs(Date.now() - Date.parse(request.at)) > 5000
        || !Number.isSafeInteger(request.policyRevision) || request.policyRevision < 0
        || typeof request.deviceRegistered !== 'boolean') return false;

    const stepUpKeys = ['verified', 'authAgeSeconds'];
    if (!isPlainDataObject(request.stepUp, stepUpKeys)
        || typeof request.stepUp.verified !== 'boolean'
        || (request.stepUp.verified
          ? !Number.isSafeInteger(request.stepUp.authAgeSeconds)
            || request.stepUp.authAgeSeconds < 0 || request.stepUp.authAgeSeconds > 900
          : request.stepUp.authAgeSeconds !== null)) return false;

    if (!validRecentEvents(request.recentEvents)) return false;

    const signalKeys = ['source', 'region', 'network', 'hour'];
    if (!isPlainDataObject(request.signals, signalKeys)
        || typeof request.signals.source !== 'string'
        || request.signals.source.length === 0 || request.signals.source.length > 80
        || typeof request.signals.region !== 'string'
        || request.signals.region.length === 0 || request.signals.region.length > 80
        || typeof request.signals.network !== 'string'
        || request.signals.network.length === 0 || request.signals.network.length > 80
        || !Number.isInteger(request.signals.hour)
        || request.signals.hour < 0 || request.signals.hour > 23) return false;

    // The live contract currently supplies no trusted region/network source.
    // Keep that documented empty-source representation from claiming either signal.
    if (request.signals.source === 'none'
        && (request.signals.region !== 'unknown' || request.signals.network !== 'unknown')) {
      return false;
    }
    return true;
  } catch {
    // Proxies, getters, malformed dates, and other non-JSON input fail closed.
    return false;
  }
}

function hasCompositeAnomaly(request) {
  const { signals, recentEvents } = request;
  // source is descriptive, not an authentication token or an allow-listed enum.
  // The engine supplies the request; use the contract's actual hour/network/event fields.
  const unusualHour = signals.hour <= 5 || signals.hour >= 23;
  const firstSeenNetwork = signals.network === 'first_seen';
  const recentBulkRead = recentEvents.some(event => event.kind === 'bulk_read'
    && event.ageSeconds <= RECENT_EVENT_WINDOW_SECONDS
    && event.count >= BULK_READ_MIN_COUNT);

  return unusualHour && firstSeenNetwork && recentBulkRead;
}

function responseRequestId(request) {
  try {
    if (request === null || typeof request !== 'object') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(request, 'requestId');
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

export async function decide(request) {
  const valid = validRequest(request);
  const isRegistered = valid && request.deviceRegistered === true;
  const needsStepUp = isRegistered && hasCompositeAnomaly(request);
  return {
    schema: 'aleph.decision.v1',
    requestId: valid ? request.requestId : responseRequestId(request),
    decision: !isRegistered ? 'deny' : needsStepUp ? 'step_up' : 'allow',
    // The new reason code must also be present in the operator's allowedReasonCodes registry.
    reasonCode: !isRegistered ? 'device_not_registered'
      : needsStepUp ? 'composite_anomaly_step_up' : 'approved',
    ruleIds: !isRegistered ? [RULE_IDS[0]]
      : needsStepUp ? [RULE_IDS[1]] : [RULE_IDS[0]],
  };
}
