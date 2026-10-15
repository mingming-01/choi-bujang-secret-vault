// 9단계 입력은 가상 사건 계약의 세 필드만 확인합니다. 사건 내용은 저장하거나 출력하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const readsBySubject = new Map();
  const windowMs = 10 * 60 * 1000;

  for (const event of events) {
    if (event === null || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('invalid_detection_event');
    }

    const at = event.at;
    const method = event.method;
    const identity = event.identity;
    const sub =
      identity !== null &&
      typeof identity === 'object' &&
      !Array.isArray(identity)
        ? identity.sub
        : undefined;

    if (
      typeof at !== 'string' ||
      typeof method !== 'string' ||
      typeof sub !== 'string'
    ) {
      throw new TypeError('invalid_detection_event');
    }

    const timestamp = Date.parse(at);

    if (!Number.isFinite(timestamp)) {
      throw new TypeError('invalid_detection_event');
    }

    if (method !== 'GET') continue;

    if (!readsBySubject.has(sub)) {
      readsBySubject.set(sub, []);
    }

    readsBySubject.get(sub).push(timestamp);
  }

  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);

    let start = 0;

    for (let end = 0; end < timestamps.length; end++) {
      while (timestamps[end] - timestamps[start] > windowMs) {
        start++;
      }

      if (end - start + 1 > 120) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return { action: 'observe' };
}
