// Self-contained classifier: no imports, file I/O, or network access.
const SQL_SYNTAX = /\bunion\s+(?:all\s+)?select\b|\bselect\s+[\w`'"*.,()+%\-\s]{1,100}\s+from\s+[\w`".]+|(?:\bor\b|\band\b)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--(?:\s|$)|\/\*/i;
const SCRIPT_TAG = /<\s*\/?\s*script\b[^>]*>/i;
const REPEATED_PATH_TRAVERSAL = /(?:\.\.[/\\]){2,}/i;
const PATTERNS = [
  { id: 'sql-injection', name: '요청 데이터의 SQL 주입 구문', test: SQL_SYNTAX },
  { id: 'script-tag', name: '요청 데이터의 실제 script 태그', test: SCRIPT_TAG },
  { id: 'path-traversal', name: '요청 데이터의 반복 ../ 경로 탐색', test: REPEATED_PATH_TRAVERSAL },
];

function decodeRequest(value) {
  let decoded = value.replace(/\+/g, ' ');
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

function parseIpv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets;
}

function parseIpv6(value) {
  if (!value.includes(':') || value.includes('%')) return null;
  let input = value.toLowerCase();

  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4 = parseIpv4(input.slice(lastColon + 1));
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    input = `${input.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const compressionIndex = input.indexOf('::');
  if (compressionIndex !== -1 && input.indexOf('::', compressionIndex + 2) !== -1) return null;
  const hasCompression = compressionIndex !== -1;
  const leftText = hasCompression ? input.slice(0, compressionIndex) : input;
  const rightText = hasCompression ? input.slice(compressionIndex + 2) : '';
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...right];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;

  if (hasCompression) {
    if (groups.length >= 8) return null;
    const zeros = Array(8 - groups.length).fill('0');
    return [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16));
  }
  if (groups.length !== 8) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

function getValidSource(alert) {
  const source = alert?.data?.srcip;
  if (typeof source !== 'string') return '';
  const normalized = source.trim();
  const ipv4 = parseIpv4(normalized);
  if (ipv4) return `ipv4:${ipv4.join('.')}`;
  const ipv6 = parseIpv6(normalized);
  return ipv6 ? `ipv6:${ipv6.map((group) => group.toString(16).padStart(4, '0')).join(':')}` : '';
}

function getDescription(alert) {
  if (typeof alert?.description === 'string') return alert.description;
  if (typeof alert?.rule?.description === 'string') return alert.rule.description;
  return '';
}

// Metadata can justify review, but never establishes a request attack pattern
// or repeated-alert evidence. Descriptions claiming repetition are ignored.
function hasAmbiguousMetadata(alert) {
  const description = getDescription(alert);
  if (/따옴표|이상한\s*검색|구분\s*문자|주입처럼\s*보이는/i.test(description)) return true;
  const level = alert?.rule?.level;
  const mitre = alert?.rule?.mitre;
  return Number.isFinite(level) && level >= 10 && Array.isArray(mitre) && mitre.includes('T1190');
}

function getRequestPatterns(alert) {
  const requestText = getRequestText(alert);
  return PATTERNS.filter((pattern) => pattern.test.test(requestText));
}

function hasRepeatedCorrelation(alert, sourceAddress, patternId) {
  const evidence = alert?.correlationEvidence;
  const alertId = alert?.id;
  if (typeof alertId !== 'string' || alertId.length === 0) return false;
  if (evidence?.sourceAddress !== sourceAddress || evidence?.patternId !== patternId) return false;
  if (!Array.isArray(evidence.alertIds) || !evidence.alertIds.includes(alertId)) return false;
  const uniqueIds = new Set(evidence.alertIds.filter((id) => typeof id === 'string' && id.length > 0));
  return uniqueIds.size >= 2 && uniqueIds.size === evidence.alertIds.length;
}

export function decide(alert) {
  const matched = getRequestPatterns(alert);
  const sourceAddress = getValidSource(alert);
  const metadataHint = hasAmbiguousMetadata(alert);

  if (matched.length > 1) {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `서로 다른 요청 공격 신호가 함께 있어 확정 차단하지 않습니다: ${matched.map((pattern) => pattern.name).join(', ')}.`,
    };
  }

  if (matched.length === 1) {
    const pattern = matched[0];
    const repeated = sourceAddress !== '' && hasRepeatedCorrelation(alert, sourceAddress, pattern.id);
    if (repeated) {
      return {
        action: 'block',
        confidence: 0.92,
        reason: `유효한 출발지에서 동일 패턴의 별도 경보 반복을 확인했습니다: ${pattern.name}.`,
      };
    }
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `요청 데이터에서 ${pattern.name} 신호를 확인했지만, 동일 출발지의 별도 경보 반복 근거가 없어 차단하지 않습니다.`,
    };
  }

  if (metadataHint) {
    return {
      action: 'alert',
      confidence: 0.56,
      reason: '요청 공격 패턴은 확정되지 않았지만, 경보 메타데이터의 모호한 정황을 검토하도록 알립니다.',
    };
  }

  return {
    action: 'record',
    confidence: 0.08,
    reason: '요청 데이터에서 지정된 주입 신호가 확인되지 않아 정상 이벤트로 기록합니다.',
  };
}
