// Self-contained classifier. It performs no file, network, or module I/O.
const SQL_SYNTAX = /\bunion\s+(?:all\s+)?select\b|\bselect\s+[\w`'"*.,()+%\-\s]{1,100}\s+from\s+[\w`".]+|(?:\bor\b|\band\b)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--(?:\s|$)|\/\*/i;
const SCRIPT_TAG = /<\s*\/?\s*script\b[^>]*>/i;
const PATH_TRAVERSAL = /(?:\.\.[/\\]){2,}/i;
const SINGLE_PATH_TRAVERSAL = /\.\.[/\\]/i;
const PATTERNS = [
  { id: 'sql-injection', name: '요청 데이터의 SQL 주입 구문', test: SQL_SYNTAX },
  { id: 'script-tag', name: '요청 데이터의 실제 script 태그', test: SCRIPT_TAG },
  { id: 'path-traversal', name: '요청 데이터의 반복 ../ 경로 탐색', test: PATH_TRAVERSAL },
];

function decodeRequest(value) {
  let decoded = value.replace(/\+/g, ' ');
  // Decode ordinary and double-encoded request data without failing on malformed escapes.
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function getRequestText(alert) {
  const url = alert?.data?.url;
  return typeof url === 'string' ? decodeRequest(url) : '';
}

function getDescription(alert) {
  if (typeof alert?.description === 'string') return alert.description;
  if (typeof alert?.rule?.description === 'string') return alert.rule.description;
  return '';
}

function getValidSource(alert) {
  const source = alert?.data?.srcip;
  if (typeof source !== 'string') return '';
  const normalized = source.trim();
  const octets = normalized.split('.');
  if (octets.length !== 4) return '';
  const valid = octets.every((octet) => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
  return valid ? normalized : '';
}

function hasSuspiciousMetadata(description) {
  // Explicitly benign descriptions do not become suspicious merely by mentioning a keyword.
  const normalized = description
    .replace(/(?:삽입\s*표식|공격\s*표기)(?:은|는)?\s*(?:아닙니다|없습니다)/g, ' ');
  return /\bSQL\b.{0,24}(?:구문|표기|injection|주입)|(?:스크립트|script).{0,20}(?:삽입|태그|표식)|(?:경로|path).{0,24}(?:이탈|탐색|거슬러|올라가|traversal)|데이터베이스.{0,20}(?:조회|쿼리).{0,20}(?:붙|표기)|명령.{0,12}구분자|구분\s*문자|따옴표|주입처럼\s*보이는|이상한\s*검색|공격\s*표기/i.test(normalized);
}

/**
 * Extracts signals from request data separately from alert-description metadata.
 * The runner uses these stable pattern IDs to correlate independent alerts.
 */
export function analyzeAlert(alert) {
  const requestText = getRequestText(alert);
  return {
    sourceAddress: getValidSource(alert),
    patterns: PATTERNS.filter((pattern) => pattern.test.test(requestText)).map((pattern) => pattern.id),
    suspiciousRequest: SINGLE_PATH_TRAVERSAL.test(requestText),
    suspiciousMetadata: hasSuspiciousMetadata(getDescription(alert)),
  };
}

function hasRepeatedCorrelation(alert, sourceAddress, patternId) {
  const evidence = alert?.correlationEvidence;
  return evidence?.sourceAddress === sourceAddress
    && evidence?.patternId === patternId
    && Number.isSafeInteger(evidence?.occurrences)
    && evidence.occurrences >= 2;
}

export function decide(alert) {
  const analysis = analyzeAlert(alert);
  const matched = PATTERNS.filter((pattern) => analysis.patterns.includes(pattern.id));

  if (matched.length > 1) {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `서로 다른 요청 공격 신호가 함께 있어 확정 차단하지 않습니다: ${matched.map((pattern) => pattern.name).join(', ')}.`,
    };
  }

  if (matched.length === 1) {
    const pattern = matched[0];
    if (
      analysis.sourceAddress !== ''
      && hasRepeatedCorrelation(alert, analysis.sourceAddress, pattern.id)
    ) {
      return {
        action: 'block',
        confidence: 0.92,
        reason: `유효한 출발지에서 동일 요청 패턴의 별도 경보 반복 확인: ${pattern.name}.`,
      };
    }
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `요청 데이터에서 ${pattern.name} 신호를 확인했지만, 동일 출발지·동일 패턴의 별도 경보 반복 근거가 부족합니다.`,
    };
  }

  if (analysis.suspiciousRequest || analysis.suspiciousMetadata) {
    return {
      action: 'alert',
      confidence: 0.56,
      reason: '요청 데이터 또는 경보 메타데이터에 의심 정황이 있으나 차단에 필요한 명확한 반복 신호가 부족합니다.',
    };
  }

  return {
    action: 'record',
    confidence: 0.08,
    reason: '요청 데이터에서 주입 신호가 확인되지 않아 정상 이벤트로 기록합니다.',
  };
}
