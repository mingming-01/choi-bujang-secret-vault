const REQUEST_FIELDS = ['data.url', 'data.uri', 'url', 'requestUrl', 'request'];
const DEFAULT_PATTERNS = [
  { id: 'sql-injection', regex: /\bunion\s+(?:all\s+)?select\b|\bselect\s+[\w`'"*.,()+%\-\s]{1,100}\s+from\s+[\w`".]+|(?:\bor\b|\band\b)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--(?:\s|$)|\/\*/i },
  { id: 'script-tag', regex: /<\s*\/?\s*script\b[^>]*>/i },
  { id: 'path-traversal', regex: /(?:\.\.[/\\]){2,}/i },
];
const DEFAULT_AMBIGUOUS_PATTERNS = [
  { id: 'partial-sql', regex: /\bunion\s+(?:all\s+)?$|\bselect\s+(?:\*|[\w`"']+(?:\s*,\s*[\w`"']+)*)\s*$/i },
  { id: 'partial-script-tag', regex: /<\s*\/?\s*script\b(?![^>]*>)/i },
  { id: 'single-traversal-segment', regex: /(?:\.\.[/\\])/i },
  { id: 'isolated-quote', regex: /['"](?=$|[&#\s])|(?<=[?&=])['"]/i },
  { id: 'command-separator', regex: /(?:;|&&|\|\|)\s*(?:whoami|id|uname|cat|curl|wget|sh|bash)\b/i },
];

function compileDefinitions(definitions) {
  if (!Array.isArray(definitions)) return [];
  return definitions.flatMap((definition) => {
    if (!definition || typeof definition.id !== 'string' || typeof definition.source !== 'string') return [];
    try {
      return [{ id: definition.id, regex: new RegExp(definition.source, typeof definition.flags === 'string' ? definition.flags.replace(/[gy]/g, '') : '') }];
    } catch {
      return [];
    }
  });
}

function getSettings(alert) {
  const config = alert?.webInjectionConfig;
  if (!config || config.schema !== 'aleph.xdr.web-injection-patterns.v1') {
    return {
      requestFields: REQUEST_FIELDS,
      decodePasses: 2,
      patterns: DEFAULT_PATTERNS,
      ambiguousPatterns: DEFAULT_AMBIGUOUS_PATTERNS,
    };
  }
  return {
    requestFields: Array.isArray(config.requestFields)
      ? config.requestFields.filter((field) => typeof field === 'string')
      : REQUEST_FIELDS,
    decodePasses: Number.isInteger(config.decodePasses)
      ? Math.max(0, Math.min(config.decodePasses, 4))
      : 2,
    patterns: compileDefinitions(config.patterns),
    ambiguousPatterns: compileDefinitions(config.ambiguousPatterns),
  };
}

function getPathValue(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function decodeText(value, decodePasses) {
  let text = String(value ?? '').replace(/\+/g, ' ');
  for (let i = 0; i < decodePasses; i += 1) {
    try {
      const decoded = decodeURIComponent(text);
      if (decoded === text) break;
      text = decoded;
    } catch {
      break;
    }
  }
  return text;
}

function getRequestText(alert, settings) {
  return settings.requestFields
    .map((field) => getPathValue(alert, field))
    .filter((value) => typeof value === 'string')
    .map((value) => decodeText(value, settings.decodePasses))
    .join(' ');
}

function matchingIds(text, patterns) {
  return patterns.filter(({ regex }) => regex.test(text)).map(({ id }) => id);
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
  const compressed = compressionIndex !== -1;
  const leftText = compressed ? input.slice(0, compressionIndex) : input;
  const rightText = compressed ? input.slice(compressionIndex + 2) : '';
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...right];
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return null;
  if (compressed) {
    if (groups.length >= 8) return null;
    const zeros = Array(8 - groups.length).fill('0');
    return [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16));
  }
  if (groups.length !== 8) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

function normalizeSource(value) {
  if (typeof value !== 'string') return '';
  const source = value.trim();
  if (!source || /[\s/]/.test(source)) return '';
  const ipv4 = parseIpv4(source);
  if (ipv4) return `ipv4:${ipv4.join('.')}`;
  const ipv6 = parseIpv6(source);
  if (!ipv6) return '';
  return `ipv6:${ipv6.map((group) => group.toString(16).padStart(4, '0')).join(':')}`;
}

function getValidSource(alert) {
  for (const candidate of [alert?.sourceAddress, alert?.source, alert?.data?.srcip]) {
    const normalized = normalizeSource(candidate);
    if (normalized) return normalized;
  }
  return '';
}

function result(action, confidence, reason) {
  return { action, confidence, reason: String(reason).replace(/[\r\n]+/g, ' ').slice(0, 240) };
}

function isValidAlertId(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 200
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function hasValidCorrelation(alert, patternName, source) {
  const correlation = alert?.correlationEvidence;
  if (!source || !correlation || typeof correlation !== 'object' || Array.isArray(correlation)) return false;
  const keys = Object.keys(correlation).sort();
  if (keys.length !== 3 || keys.join(',') !== 'alertIds,patternId,sourceAddress') return false;
  if (
    correlation.patternId !== patternName
    || correlation.sourceAddress !== source
    || !Array.isArray(correlation.alertIds)
    || correlation.alertIds.length < 2
    || !correlation.alertIds.every(isValidAlertId)
  ) return false;
  const alertIds = new Set(correlation.alertIds);
  const alertId = alert?.id;
  return alertIds.size === correlation.alertIds.length
    && isValidAlertId(alertId)
    && alertIds.has(alertId);
}

// Pure decision: request evidence determines severity; only runner-supplied,
// validated distinct-event correlation can elevate a single pattern to block.
export function decide(alert) {
  const settings = getSettings(alert);
  const requestText = getRequestText(alert, settings);
  const source = getValidSource(alert);
  const patterns = matchingIds(requestText, settings.patterns);

  if (patterns.length > 1) {
    return result('alert', 0.68, 'ambiguous-pattern-overlap: 여러 공격 유형이 겹침');
  }

  if (patterns.length === 0) {
    if (matchingIds(requestText, settings.ambiguousPatterns).length > 0) {
      return result('alert', 0.6, 'ambiguous-request-signal: 요청 데이터에 불완전하거나 의심스러운 신호가 있어 검토 대상으로 분류');
    }
    return result('record', 0.08, 'normal-or-unsupported: 요청에서 지정된 공격 패턴 또는 모호 신호가 확인되지 않음');
  }

  const patternName = patterns[0];
  if (hasValidCorrelation(alert, patternName, source)) {
    return result('block', 0.92, `${patternName}: 유효한 출처에서 서로 다른 경보 ID의 동일 패턴 반복 확인`);
  }
  return result('alert', 0.68, `${patternName}: 공격 패턴은 확인됐지만 반복 차단 조건이 부족함`);
}
