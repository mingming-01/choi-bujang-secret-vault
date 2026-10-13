// Self-contained classifier: one alert in, one decision out. Optional runner evidence is attached
// only to cloned alerts by scripts/xdr-run.mjs; standalone calls infer no cross-alert repetition.
const SQL_SYNTAX = /\b(?:union\s+(?:all\s+)?select|select\s+[\w'"%()+\-\s]{1,80}\s+from|(?:or|and)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--|\/\*)/i;
const SCRIPT_TAG = /<\s*\/?\s*script\b/i;
const PATH_TRAVERSAL = /\.\.\//;
const CANDIDATE_PREFIX = '분류용 후보:';
const RUNNER_EVIDENCE_KEY = '__xdrRunnerRepeatEvidence';
const RUNNER_CLASSIFY_KEY = '__xdrRunnerClassifyOnly';

const PATTERNS = [
  {
    name: '요청 매개변수의 SQL 구문',
    matches: ({ requestText, description }) => SQL_SYNTAX.test(requestText)
      || /SQL\s*(?:구문(?:\s*(?:표기|을\s*이어\s*붙인))?|표기|표식)/i.test(description)
      || /데이터베이스\s*조회(?:를|가)?\s*이어\s*붙이는\s*표기/i.test(description)
      || /\bSQL\s+injection\b/i.test(description),
  },
  {
    name: '스크립트 태그 삽입 표기',
    matches: ({ requestText, description }) => SCRIPT_TAG.test(requestText)
      || /스크립트\s*(?:삽입\s*(?:표기|표식)|표기|표식|태그)/i.test(description),
  },
  {
    name: '반복 경로 탐색 표기 ../',
    matches: ({ requestText, description }) => PATH_TRAVERSAL.test(requestText)
      || /경로(?:를\s*여러\s*단계\s*거슬러\s*올라가는\s*표기|\s*이탈\s*표기)/i.test(description),
  },
];

function decode(value) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

function getText(alert) {
  const requestText = typeof alert?.data?.url === 'string' ? decode(alert.data.url) : '';
  const queryStart = requestText.indexOf('?');
  const query = queryStart < 0 ? '' : requestText.slice(queryStart + 1).split('#', 1)[0];
  const description = typeof alert?.description === 'string'
    ? alert.description
    : typeof alert?.rule?.description === 'string'
      ? alert.rule.description
      : '';
  return { requestText, query: decode(query), description };
}

function getValidSource(alert) {
  const source = alert?.data?.srcip;
  if (typeof source !== 'string') return '';
  const normalized = source.trim();
  const octets = normalized.split('.');
  const valid = octets.length === 4 && octets.every((octet) => {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(octet)) return false;
    return Number(octet) <= 255;
  });
  return valid ? normalized : '';
}

// data.count is deliberately ignored. Repetition stated here is evidence only for this event.
function hasEventRepeat(description) {
  if (/(?:반복은\s*없|반복되지\s*않|연속\s*요청은\s*없)/i.test(description)) return false;
  const explicitCount = description.match(/(\d+)\s*번\s*(?:반복|들어왔|나왔)/);
  if (explicitCount) return Number(explicitCount[1]) >= 2;
  return /(?:반복(?:됐|되었|되거나|해서|하여|합니다|함)|연속\s*요청)/i.test(description);
}

function getRunnerRepeatCount(alert, source, patternName) {
  const evidence = alert?.[RUNNER_EVIDENCE_KEY];
  if (evidence?.source !== source || evidence?.patternName !== patternName) return 0;
  return Number.isSafeInteger(evidence.count) && evidence.count >= 2 ? evidence.count : 0;
}

function getAmbiguousReason(description) {
  if (/(?:따옴표.{0,8}(?:한\s*번|1\s*번)|(?:이상한\s*검색|주입처럼\s*보이는\s*표기|구분\s*문자).{0,18}(?:1\s*건|한\s*건)|명령\s*구분자\s*표기)/i.test(description)) {
    return '불완전하거나 정의된 범위 밖의 의심 표기만 확인되어 추가 검토가 필요합니다.';
  }
  return '';
}

function classify(alert) {
  const text = getText(alert);
  return { text, source: getValidSource(alert), matched: PATTERNS.filter((pattern) => pattern.matches(text)) };
}

export function decide(alert) {
  const { text, source, matched } = classify(alert);

  if (alert?.[RUNNER_CLASSIFY_KEY] === true && source !== '' && matched.length === 1) {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `${CANDIDATE_PREFIX} ${matched[0].name}`,
    };
  }

  if (matched.length > 1) {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `서로 다른 공격 패턴이 겹쳐 단일 공격으로 확정하지 않습니다: ${matched.map((pattern) => pattern.name).join(' 및 ')}.`,
    };
  }

  if (matched.length === 1) {
    const pattern = matched[0];
    const repeatedByRunner = source !== '' && getRunnerRepeatCount(alert, source, pattern.name) >= 2;
    if (source !== '' && (hasEventRepeat(text.description) || repeatedByRunner)) {
      return {
        action: 'block',
        confidence: 0.92,
        reason: `반복 근거와 유효한 출발지 주소: ${pattern.name}`,
      };
    }

    return {
      action: 'alert',
      confidence: 0.68,
      reason: `${CANDIDATE_PREFIX} ${pattern.name} — 단일 경보만으로는 반복 차단 근거가 부족합니다.`,
    };
  }

  const ambiguousReason = getAmbiguousReason(text.description);
  if (ambiguousReason !== '') {
    return { action: 'alert', confidence: 0.56, reason: ambiguousReason };
  }

  return {
    action: 'record',
    confidence: 0.08,
    reason: '요청에서 명시적인 SQL 구문·스크립트 태그·경로 탐색 징후를 확인하지 못해 정상 입력으로 기록합니다.',
  };
}
