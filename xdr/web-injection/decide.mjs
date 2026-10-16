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

  const evidenceSource = typeof correlation.sourceAddress === 'string'
    ? normalizeSource(correlation.sourceAddress.replace(/^(?:ipv4|ipv6):/, ''))
    : '';
  if (!evidenceSource || evidenceSource !== source) return false;

  if (correlation.patternId !== undefined && correlation.patternId !== patternName) return false;

  const ids = correlation.alertIds;
  if (
    !Array.isArray(ids)
    || ids.length === 0
    || !ids.every(isValidAlertId)
    || new Set(ids).size !== ids.length
    || !isValidAlertId(alert?.id)
  ) return false;

  return ids.some((id) => id !== alert.id);
}

function hasRepeatedCountEvidence(alert, source) {
  if (!source) return false;
  const raw = alert?.data?.count;
  const count = typeof raw === 'number'
    ? raw
    : typeof raw === 'string' && /^\d+$/.test(raw.trim())
      ? Number(raw.trim())
      : NaN;
  return Number.isSafeInteger(count) && count >= 2;
}

// Request signals decide the severity: SQL syntax, script tag, repeated ../ are clear;
// partial forms are ambiguous; a lone quote or command separator is not a task signal.
export function decide(alert) {
  const settings = getSettings(alert);
  const requestText = getRequestText(alert, settings);
  const source = getValidSource(alert);
  const patterns = matchingIds(requestText, settings.patterns);

  if (patterns.length === 0) {
    const ambiguous = matchingIds(requestText, settings.ambiguousPatterns)
      .filter((id) => id !== 'isolated-quote' && id !== 'command-separator');
    if (ambiguous.length > 0) {
      return result('alert', 0.6, 'ambiguous-request-signal: incomplete or uncertain request pattern matched');
    }
    return result('record', 0.08, 'normal-or-unsupported: no task injection signal in the request');
  }

  const repeated = hasRepeatedCountEvidence(alert, source)
    || (patterns.length === 1 && hasValidCorrelation(alert, patterns[0], source));
  if (repeated) {
    return result('block', 0.92, patterns.join('+') + ': clear injection pattern repeated from the same valid source');
  }

  return result('alert', 0.68, patterns.join('+') + ': clear injection pattern matched without repeat evidence');
}
