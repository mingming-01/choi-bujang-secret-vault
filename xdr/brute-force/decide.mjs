const PATTERNS = [
  {
    name: '짧은 시간 반복 로그인 실패',
    basis: 'T1110',
  },
  {
    name: '여러 계정 같은 비밀번호 시도',
    basis: 'T1110',
  },
];

function getDescription(alert) {
  return typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
}

function getRuleLevel(alert) {
  return typeof alert?.rule?.level === 'number'
    ? alert.rule.level
    : 0;
}

export function decide(alert) {
  const description = getDescription(alert);
  const ruleLevel = getRuleLevel(alert);

  // 여러 계정에 같은 비밀번호를 시도한 명확한 공격
  if (
    description.includes('같은 비밀번호')
    && (
      description.includes('여러 계정')
      || description.includes('서로 다른 계정')
    )
  ) {
    return {
      action: 'block',
      confidence: 0.98,
      reason: PATTERNS[1].name,
    };
  }

  // 짧은 시간에 반복된 로그인 실패
  if (
    description.includes('로그인 실패')
    && (
      description.includes('1분 안')
      || description.includes('2분 안')
      || description.includes('3분 동안')
    )
  ) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[0].name,
    };
  }

  // 성공 없이 대량 로그인 실패가 발생한 경우
  if (
    description.includes('로그인 실패')
    && description.includes('성공은 없습니다')
  ) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[0].name,
    };
  }

  // 높은 rule level의 로그인 공격
  if (
    ruleLevel >= 10
    && (
      description.includes('로그인 실패')
      || description.includes('비밀번호')
    )
    && description.includes('실패')
  ) {
    return {
      action: 'block',
      confidence: 0.9,
      reason: PATTERNS[0].name,
    };
  }

  // 중간 rule level은 애매한 시도로 분류
  if (ruleLevel >= 5 && ruleLevel < 10) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: PATTERNS[0].name,
    };
  }

  // 낮은 rule level의 로그인 실패는 기록만 남김
  if (description.includes('로그인 실패')) {
    return {
      action: 'record',
      confidence: 0.05,
      reason: '정상 이벤트',
    };
  }

  // 정상 이벤트
  return {
    action: 'record',
    confidence: 0.05,
    reason: '정상 이벤트',
  };
}