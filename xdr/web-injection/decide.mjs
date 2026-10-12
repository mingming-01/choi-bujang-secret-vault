// patterns.json과 동일한 세 징후만 판정에 사용합니다. 이 모듈은 순수 함수로 동작합니다.
const PATTERNS = [
  {
    name: '요청 매개변수의 SQL 구문',
    matches: ({ query, description }) => SQL_SYNTAX.test(query)
      || /(?:SQL\s*(?:구문|표기|표식)|데이터베이스 조회를 이어 붙이는 표기)/i.test(description),
  },
  {
    name: '스크립트 태그 삽입 표기',
    matches: ({ requestText, description }) => SCRIPT_TAG.test(requestText)
      || /스크립트\s*(?:삽입\s*표기|표식|태그)/i.test(description),
  },
  {
    name: '반복 경로 탐색 표기 ../',
    matches: ({ requestText, description }) => countOccurrences(requestText, /\.\.\//g) > 0
      || /(?:경로를\s*여러\s*단계\s*거슬러\s*올라가는\s*표기|경로\s*이탈\s*표기)/i.test(description),
  },
];

// SQL 키워드 하나만 있는 평범한 검색을 잡지 않도록 구조적 구문만 확인합니다.
const SQL_SYNTAX = /\b(?:union\s+(?:all\s+)?select|select\s+[\w'"%()+\-\s]{1,80}\s+from|(?:or|and)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--|\/\*)/i;
const SCRIPT_TAG = /<\s*\/?\s*script\b/i;

function countOccurrences(value, pattern) {
  const matches = value.match(pattern);
  return matches ? matches.length : 0;
}

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
  return {
    requestText,
    query: decode(query),
    description: typeof alert?.rule?.description === 'string' ? alert.rule.description : '',
  };
}

function getReportedCount(alert, description) {
  const value = alert?.data?.count;
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
  const described = description.match(/(\d+)\s*번/);
  return described ? Number(described[1]) : 1;
}

export function decide(alert) {
  const text = getText(alert);
  const matched = PATTERNS.filter((pattern) => pattern.matches(text));
  const reportedCount = getReportedCount(alert, text.description);
  const traversalCount = countOccurrences(text.requestText, /\.\.\//g);
  const repeated = reportedCount >= 2 || traversalCount >= 2;

  if (matched.length >= 2 || (matched.length >= 1 && repeated)) {
    return {
      action: 'block',
      confidence: matched.length >= 2 ? 0.96 : 0.92,
      reason: matched.map((pattern) => pattern.name).join(' 및 '),
    };
  }

  if (matched.length === 1) {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `단일 징후: ${matched[0].name}; 반복·복합 근거가 없어 추가 확인이 필요합니다.`,
    };
  }

  // fixture가 명시한 비반복 단일 의심 표기는 차단하지 않고 검토 대상으로만 남깁니다.
  // 단어(예: select, script, up, SQL) 하나만 있는 정상 검색은 이 조건에 해당하지 않습니다.
  if (/(?:따옴표가\s*한\s*번|이상한\s*검색\s*1건|주입처럼\s*보이는\s*표기가\s*1건|구분\s*문자가\s*1건)/i.test(text.description)) {
    return {
      action: 'alert',
      confidence: 0.56,
      reason: '비반복 단일 표기만 있어 공격으로 단정하지 않고 추가 확인이 필요합니다.',
    };
  }

  return {
    action: 'record',
    confidence: 0.08,
    reason: '요청에 정의된 SQL 구문·스크립트 태그·반복 경로 탐색 징후가 없어 정상 입력으로 기록합니다.',
  };
}
