import { readFile } from 'node:fs/promises';

const RULES_RESULT = new URL('../xdr/web-injection/result.json', import.meta.url);
const PATTERNS_FILE = new URL('../xdr/web-injection/patterns.json', import.meta.url);
const PERSISTENCE_RESULT = new URL('../xdr/persistence/result.json', import.meta.url);
const PRIVILEGE_RESULT = new URL('../xdr/privilege/result.json', import.meta.url);

function parseIpv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4 || !parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part))) return null;
  const octets = parts.map(Number);
  return octets.every((octet) => octet <= 255) ? octets : null;
}

function normalizeSource(value) {
  if (typeof value !== 'string') return '';
  const input = value.trim().toLowerCase();
  if (!input || /[\s/%]/.test(input)) return '';
  const ipv4 = parseIpv4(input);
  if (ipv4) return `ipv4:${ipv4.join('.')}`;
  if (input.startsWith('::ffff:')) {
    const mapped = parseIpv4(input.slice(7));
    if (mapped) return `ipv4:${mapped.join('.')}`;
  }
  if (!input.includes(':')) return '';

  const halves = input.split('::');
  if (halves.length > 2) return '';
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = [...left, ...right];
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return '';
  if (halves.length === 2) {
    if (groups.length >= 8) return '';
    groups.splice(left.length, 0, ...Array(8 - groups.length).fill('0'));
  } else if (groups.length !== 8) {
    return '';
  }
  return `ipv6:${groups.map((group) => Number.parseInt(group, 16).toString(16).padStart(4, '0')).join(':')}`;
}

function getRequestSource(request) {
  // Prefer the platform-provided client address; never trust a caller-supplied forwarded header.
  return normalizeSource(request?.ip) || normalizeSource(request?.socket?.remoteAddress);
}

function getRequestArgumentText(request, decodePasses) {
  const requestUrl = typeof request?.url === 'string' ? request.url : '';
  const questionMark = requestUrl.indexOf('?');
  if (questionMark < 0) return '';
  const query = requestUrl.slice(questionMark + 1).split('#', 1)[0];
  return query.split('&').map((part) => {
    const equals = part.indexOf('=');
    let value = equals < 0 ? part : part.slice(equals + 1);
    value = value.replace(/\+/g, ' ');
    for (let pass = 0; pass < decodePasses; pass += 1) {
      try {
        const decoded = decodeURIComponent(value);
        if (decoded === value) break;
        value = decoded;
      } catch {
        break;
      }
    }
    return value;
  }).join(' ');
}

export function isDeniedByTemporaryRules(request, rules, patterns, now = Date.now()) {
  const source = getRequestSource(request);
  if (!source || !Number.isFinite(now)) return false;
  if (!Array.isArray(rules)) return false;
  const requestText = getRequestArgumentText(request, Number.isInteger(patterns?.decodePasses) ? patterns.decodePasses : 0);
  if (!requestText) return false;
  return rules.some((rule) => {
    if (rule?.action !== 'deny' || normalizeSource(rule.source) !== source) return false;
    const expiresAt = typeof rule.expiresAt === 'string' ? Date.parse(rule.expiresAt) : NaN;
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
    const pattern = patterns?.patterns?.find((item) => item?.id === rule.patternId);
    if (!pattern || typeof pattern.source !== 'string') return false;
    try {
      return new RegExp(pattern.source, typeof pattern.flags === 'string' ? pattern.flags.replace(/[gy]/g, '') : '').test(requestText);
    } catch {
      return false;
    }
  });
}

export function isDeniedByPersistenceRules(request, rules, now = Date.now()) {
  const source = getRequestSource(request);

  if (!source || !Number.isFinite(now) || !Array.isArray(rules)) {
    return false;
  }

  const allowedPatterns = [
    'unsigned-new-service',
    'unusual-scheduled-task',
    'startup-folder-change',
  ];

  return rules.some((rule) => {
    if (
      rule?.action !== 'deny'
      || rule?.moduleKey !== 'persistence'
      || normalizeSource(rule.source) !== source
      || typeof rule.sourceAlert !== 'string'
      || rule.sourceAlert.length === 0
      || !allowedPatterns.includes(rule.patternId)
    ) {
      return false;
    }

    const expiresAt = typeof rule.expiresAt === 'string'
      ? Date.parse(rule.expiresAt)
      : NaN;

    return Number.isFinite(expiresAt) && expiresAt > now;
  });
}

export function isDeniedByPrivilegeRules(request, rules, now = Date.now()) {
  const source = getRequestSource(request);

  if (!source || !Number.isFinite(now) || !Array.isArray(rules)) {
    return false;
  }

  const allowedPatterns = [
    'administrator-group-addition',
    'unfamiliar-admin-command',
  ];

  return rules.some((rule) => {
    if (
      rule?.action !== 'deny'
      || rule?.moduleKey !== 'privilege'
      || normalizeSource(rule.source) !== source
      || typeof rule.sourceAlert !== 'string'
      || rule.sourceAlert.length === 0
      || !allowedPatterns.includes(rule.patternId)
    ) {
      return false;
    }

    const expiresAt = typeof rule.expiresAt === 'string'
      ? Date.parse(rule.expiresAt)
      : NaN;

    return Number.isFinite(expiresAt) && expiresAt > now;
  });
}

export async function isTemporarilyDenied(request, now = Date.now()) {
  try {
    const [result, patterns] = await Promise.all([
      readFile(RULES_RESULT, 'utf8').then(JSON.parse),
      readFile(PATTERNS_FILE, 'utf8').then(JSON.parse),
    ]);

    if (isDeniedByTemporaryRules(
      request,
      result?.response?.candidateRules,
      patterns,
      now,
    )) {
      return true;
    }
  } catch {
    // 웹 주입 결과를 읽지 못해도 다른 거부 검사는 계속합니다.
  }

  try {
    const result = await readFile(PERSISTENCE_RESULT, 'utf8').then(JSON.parse);

    if (isDeniedByPersistenceRules(
      request,
      result?.response?.candidateRules,
      now,
    )) {
      return true;
    }
  } catch {
    // persistence 결과가 없으면 privilege 검사로 넘어갑니다.
  }

  try {
    const result = await readFile(PRIVILEGE_RESULT, 'utf8').then(JSON.parse);

    return isDeniedByPrivilegeRules(
      request,
      result?.response?.candidateRules,
      now,
    );
  } catch {
    return false;
  }
}
