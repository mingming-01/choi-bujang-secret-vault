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
      const flags = typeof definition.flags === 'string' ? definition.flags.replace(/[gy]/g, '') : '';
      return [{ id: definition.id, regex: new RegExp(definition.source, flags) }];
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
    patterns: Array.isArray(config.patterns)
      ? compileDefinitions(config.patterns)
      : DEFAULT_PATTERNS,
    ambiguousPatterns: Array.isArray(config.ambiguousPatterns)
      ? compileDefinitions(config.ambiguousPatterns)
      : DEFAULT_AMBIGUOUS_PATTERNS,
  };
}

function getPathValue(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function decodeParameterValue(value, decodePasses) {
  let text = value.replace(/\+/g, ' ');
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

function getParameterValues(value, decodePasses) {
  if (typeof value !== 'string') return [];

  // Accept either a URL/request target or an HTTP request line. Only the query
  // portion is inspected; the path, parameter names and protocol are excluded.
  const requestLine = value.match(/^[A-Z]+\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  const target = requestLine ? requestLine[1] : value;
  const questionMark = target.indexOf('?');
  if (questionMark < 0) return [];

  let query = target.slice(questionMark + 1);
  const fragment = query.indexOf('#');
  if (fragment >= 0) query = query.slice(0, fragment);
  if (!query) return [];

  return query.split('&').map((parameter) => {
    const equals = parameter.indexOf('=');
    const rawValue = equals < 0 ? '' : parameter.slice(equals + 1);
    // Split parameters before decoding so an encoded %26 remains within its
    // original value rather than becoming a new parameter boundary.
    return decodeParameterValue(rawValue, decodePasses);
  });
}

function getRequestValues(alert, settings) {
  return settings.requestFields
    .map((field) => getPathValue(alert, field))
    .filter((value) => typeof value === 'string')
    .flatMap((value) => getParameterValues(value, settings.decodePasses));
}

function isSpecificPartialSql(value) {
  // A bare natural-language phrase such as "select course" matches the broad
  // configured expression, but is not useful SQL evidence. Keep clear incomplete
  // syntax (UNION[/ALL], SELECT *, or a comma-separated SELECT list) reviewable.
  return /\bunion\s+(?:all\s+)?$/i.test(value)
    || /\bselect\s+\*\s*$/i.test(value)
    || /\bselect\s+[\w`'"]+\s*,\s*[\w`'"]+(?:\s*,\s*[\w`'"]+)*\s*$/i.test(value);
}

function matchingIds(values, patterns) {
  return patterns
    .filter(({ id, regex }) => values.some((value) => {
      regex.lastIndex = 0;
      if (!regex.test(value)) return false;
      return id !== 'partial-sql' || isSpecificPartialSql(value);
    }))
    .map(({ id }) => id);
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

function actionForConfidence(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

function isValidAlertId(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 200
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function hasValidCorrelation(alert, patternId, source) {
  const evidence = alert?.correlationEvidence;
  if (!source || !evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return false;

  if (Object.keys(evidence).sort().join(',') !== 'alertIds,patternId,sourceAddress') return false;
  if (evidence.patternId !== patternId || typeof evidence.sourceAddress !== 'string') return false;

  const evidenceSource = evidence.sourceAddress.replace(/^(?:ipv4|ipv6):/, '');
  if (normalizeSource(evidenceSource) !== source) return false;

  const ids = evidence.alertIds;
  if (
    !Array.isArray(ids)
    || ids.length < 2
    || !ids.every(isValidAlertId)
    || new Set(ids).size !== ids.length
    || !isValidAlertId(alert?.id)
    || !ids.includes(alert.id)
  ) {
    return false;
  }

  return true;
}

// Pure decision: only query-parameter values are pattern evidence. Repetition
// is accepted only from the runner's source-and-pattern-specific correlation.
export function decide(alert) {
  const settings = getSettings(alert);
  const requestValues = getRequestValues(alert, settings);
  const source = getValidSource(alert);
  const patterns = matchingIds(requestValues, settings.patterns);
  const ambiguousPatterns = matchingIds(requestValues, settings.ambiguousPatterns);
  const relevantAmbiguousPatterns = ambiguousPatterns.filter((id) => !(
    id === 'single-traversal-segment' && patterns.includes('path-traversal')
  ));

  if (patterns.length > 1) {
    const confidence = 0.68;
    return result(actionForConfidence(confidence), confidence, 'ambiguous-pattern-overlap: 여러 공격 유형이 요청 인자에서 겹침');
  }

  if (relevantAmbiguousPatterns.length > 0) {
    const confidence = 0.6;
    return result(actionForConfidence(confidence), confidence, 'ambiguous-request-signal: 요청 인자에 불완전하거나 의심스러운 신호가 있어 검토 대상으로 분류');
  }

  if (patterns.length === 0) {
    const confidence = 0.08;
    return result(actionForConfidence(confidence), confidence, 'normal-or-unsupported: 요청 인자에서 지정된 공격 패턴 또는 모호 신호가 확인되지 않음');
  }

  const patternId = patterns[0];
  if (hasValidCorrelation(alert, patternId, source)) {
    const confidence = 0.92;
    return result(actionForConfidence(confidence), confidence, `${patternId}: 같은 출처에서 서로 다른 경보 ID의 명확한 주입 반복 근거 확인`);
  }

  const confidence = 0.68;
  return result(actionForConfidence(confidence), confidence, `${patternId}: 명확한 공격 패턴은 확인됐지만 동일 유형 반복 근거가 부족함`);
}
