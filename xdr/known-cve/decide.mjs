// CVE-2021-44228 (Log4Shell) 형태 요청 판단. MITRE ATT&CK T1190.
// 아래 패턴은 xdr/known-cve/patterns.json 과 같은 내용입니다.
const PATTERNS = [
  { id: 'jndi-lookup', regex: /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nis|https?)\s*:/i },
];
const AMBIGUOUS_PATTERNS = [
  { id: 'jndi-keyword', regex: /\bjndi\b/i },
  { id: 'cve-id-text', regex: /\bCVE-2021-44228\b/i },
  { id: 'lookup-fragment', regex: /\$\{|\blookup\b/i },
];
const EXCLUDED_KEYS = new Set(['srcip', 'srcuser', 'count']);
const MAX_DEPTH = 3;

function collectStrings(value, depth, out) {
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (depth >= MAX_DEPTH || !value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (EXCLUDED_KEYS.has(key)) continue;
    collectStrings(item, depth + 1, out);
  }
}

function decodeText(value) {
  let text = value;
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(text);
      if (next === text) break;
      text = next;
    } catch {
      break;
    }
  }
  return text;
}

function result(action, confidence, reason) {
  return { action, confidence, reason: String(reason).replace(/[\r\n]+/g, ' ').slice(0, 240) };
}

export function decide(alert) {
  const strings = [];
  collectStrings(alert?.data, 0, strings);
  const texts = strings.map(decodeText);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;

  const clear = PATTERNS.filter(({ regex }) => texts.some((text) => regex.test(text))).map(({ id }) => id);
  if (clear.length > 0) {
    const fields = texts.filter((text) => PATTERNS.some(({ regex }) => regex.test(text))).length;
    return result('block', fields > 1 ? 0.97 : 0.95, clear[0] + ': complete JNDI lookup string in ' + fields + ' request field(s)');
  }

  const weak = AMBIGUOUS_PATTERNS.filter(({ regex }) => texts.some((text) => regex.test(text))).map(({ id }) => id);
  if (weak.length > 0) {
    return result('alert', 0.6, weak.join('+') + ': incomplete or uncertain known-CVE signal');
  }
  if (level >= 5) {
    return result('alert', 0.55, 'elevated-level: no lookup syntax but rule level ' + level);
  }
  return result('record', 0.08, 'normal-or-unsupported: no known-CVE signal');
}
