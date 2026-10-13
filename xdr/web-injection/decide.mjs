// 패턴 후보만 분류합니다. 실제 반복 판정은 순수 함수를 호출하는 실행기가
// 같은 출발지 주소의 후보 경보를 집계해 전달합니다.
const SQL_SYNTAX = /\b(?:union\s+(?:all\s+)?select|select\s+[\w'"%()+\-\s]{1,80}\s+from|(?:or|and)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--|\/\*)/i;
const SCRIPT_TAG = /<\s*\/?\s*script\b/i;
const PATH_TRAVERSAL = /\.\.\//g;
const CANDIDATE_REASON_PREFIX = '분류용 후보:';

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
    matches: ({ requestText, description }) => countOccurrences(requestText, PATH_TRAVERSAL) > 0
      || /(?:경로를\s*여러\s*단계\s*거슬러\s*올라가는\s*표기|경로\s*이탈\s*표기)/i.test(description),
  },
];

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

function getReportedCount(alert) {
  const value = alert?.data?.count;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) ? parsed : 0;
  }
  return 0;
}

function getDescribedRepeatCount(description) {
  // 설명의 숫자는 반복·유입 횟수를 명시하는 경우에만 사용합니다.
  const match = description.match(/(\d+)\s*번\s*(?:반복|들어왔|나왔)/);
  return match ? Number(match[1]) : 0;
}

function hasExplicitRepeatWording(description) {
  return /(?:반복|연속\s*요청|같은\s*주소|한\s*주소)/i.test(description)
    && !/(?:반복은\s*없|반복되지\s*않)/i.test(description);
}

// 이 과제의 fixture는 문서용 IPv4 주소를 사용합니다. decide 모듈은 Node 내장 모듈
// import 없이 실행되어야 하므로 IPv4 유효성을 순수 함수로 확인합니다.
function hasValidSource(alert) {
  const source = alert?.data?.srcip;
  if (typeof source !== 'string') return false;
  const octets = source.trim().split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(octet)) return false;
    return Number(octet) <= 255;
  });
}

function classify(alert) {
  const text = getText(alert);
  const matched = PATTERNS.filter((pattern) => pattern.matches(text));
  const description = text.description;
  const describedCount = getDescribedRepeatCount(description);
  const reportedCount = getReportedCount(alert);
  const eventRepeat = describedCount >= 2
    || (reportedCount >= 2 && hasExplicitRepeatWording(description));
  return {
    text,
    matched,
    eventRepeat,
    // Multiple pattern hits remain ambiguous and cannot feed source counts.
    clear: matched.length === 1,
  };
}

export function decide(alert, context = {}) {
  const classification = classify(alert);
  const { text, matched } = classification;
  const sourceAddress = hasValidSource(alert) ? alert.data.srcip.trim() : '';

  // 실행기의 사전 분류 단계에서만 패턴 후보를 표시합니다. 이 결과는 결과 파일이나
  // 로그에 기록되지 않으며, 최종 판정은 이벤트 반복 또는 같은 srcip 집계를 사용합니다.
  if (context?.classifyOnly === true && classification.clear && sourceAddress !== '') {
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `${CANDIDATE_REASON_PREFIX} ${matched.map((pattern) => pattern.name).join(' 및 ')}`,
    };
  }

  if (matched.length > 0) {
    const patternRepeatCount = matched.length === 1
      ? context?.sourceRepeatCounts?.[matched[0].name]
      : 0;
    const repeated = classification.clear
      && sourceAddress !== ''
      && (classification.eventRepeat
        || (Number.isSafeInteger(patternRepeatCount) && patternRepeatCount >= 2));

    if (repeated) {
      return {
        action: 'block',
        confidence: matched.length >= 2 ? 0.96 : 0.92,
        reason: matched.map((pattern) => pattern.name).join(' 및 '),
      };
    }

    const sourceNote = sourceAddress === '' ? ' 출발지 주소를 확인할 수 없어 차단하지 않습니다.' : '';
    return {
      action: 'alert',
      confidence: 0.68,
      reason: `단일 또는 반복 근거가 부족한 징후: ${matched.map((pattern) => pattern.name).join(' 및 ')}.${sourceNote}`,
    };
  }

  // 명시된 비반복 단일 의심 표기는 차단하지 않고 검토 대상으로만 남깁니다.
  // select, script, up, SQL 같은 단어 하나만 있는 정상 검색은 이 조건에 해당하지 않습니다.
  if (/(?:따옴표가\s*한\s*번|이상한\s*검색\s*1건|주입처럼\s*보이는\s*표기가\s*1건|구분\s*문자가\s*1건)/i.test(text.description)) {
    return {
      action: 'alert',
      confidence: 0.56,
      reason: '비반복 단일 표기만 있어 공격으로 단정하지 않고 추가 확인이 필요합니다.',
    };
  }

  // 세 패턴 밖에 있는 명시적 반복 표기는 차단 후보가 아닌 검토 대상으로 남깁니다.
  if (/(?:표기|징후).*(?:연속\s*요청|반복)/i.test(text.description)
    && (getDescribedRepeatCount(text.description) >= 2
      || (getReportedCount(alert) >= 2 && hasExplicitRepeatWording(text.description)))) {
    return {
      action: 'alert',
      confidence: 0.56,
      reason: '정의된 패턴 범위 밖의 반복 의심 표기이므로 차단하지 않고 검토 대상으로 남깁니다.',
    };
  }

  return {
    action: 'record',
    confidence: 0.08,
    reason: '요청에 정의된 SQL 구문·스크립트 태그·반복 경로 탐색 징후가 없어 정상 입력으로 기록합니다.',
  };
}
