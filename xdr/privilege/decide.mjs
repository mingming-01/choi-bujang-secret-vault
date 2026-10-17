const PATTERNS = [
  {
    id: 'administrator-group-addition',
    name: '일반 계정의 관리자 그룹 추가',
    condition: '일반 계정의 관리자 그룹 추가와 낯선 출발지, 복수 계정, 반복 등록 또는 권한 명령 등 추가 정황을 함께 확인한다.',
    basis: 'T1078: 정상 계정에 관리자 권한이 부여되거나 권한이 재등록된 정황을 확인한다.',
  },
  {
    id: 'unfamiliar-admin-command',
    name: '낯선 출발지 또는 권한 변경 직후의 관리자 명령',
    condition: '처음 보는 주소, 방금 발생한 관리자 권한 변경 또는 다른 계정의 권한을 이용한 관리자 명령을 확인한다.',
    basis: 'T1068 및 T1078: 구체적인 권한 상승 또는 계정 오용 정황을 근거로 판단한다.',
  },
  {
    id: 'off-hours-privilege-use',
    name: '업무 시간 밖의 권한 사용',
    condition: '업무 시간 밖이라는 정보는 실제 권한 관련 활동이 확인될 때만 보조 신호로 사용한다.',
    basis: 'T1078: 시간대는 보조적인 맥락이며 시간 정보만으로 공격을 확정하지 않는다.',
  },
];

const AMBIGUOUS_PATTERNS = [
  {
    id: 'uncertain-elevation',
    name: '확정되지 않은 권한 상승',
    matches: (description) => /권한 상승/.test(description),
  },
  {
    id: 'single-or-failed-admin-command',
    name: '단발성 또는 실패한 관리자 명령',
    matches: (description) => /관리자 명령|권한 명령/.test(description),
  },
  {
    id: 'uncertain-group-change',
    name: '일반 그룹 변경 또는 생성',
    matches: (description) =>
      /그룹에 추가됐|그룹에 추가되|새 로컬 그룹.*만들어졌|그룹 설명.*바뀌/.test(description),
  },
  {
    id: 'account-type-discovery',
    name: '계정 종류 조회',
    matches: (description) => /계정 종류를 조회|계정 유형을 조회/.test(description),
  },
];

function getDescription(alert) {
  return typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
}

function getCount(alert) {
  const value = alert?.data?.count;

  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }

  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const count = Number(value.trim());
    return Number.isSafeInteger(count) ? count : 0;
  }

  return 0;
}

function result(action, confidence, reason) {
  return {
    action,
    confidence,
    reason: String(reason).replace(/[\r\n]+/g, ' ').slice(0, 240),
  };
}

export function decide(alert) {
  const description = getDescription(alert);
  const group = typeof alert?.data?.group === 'string'
    ? alert.data.group.toLowerCase()
    : '';

  const administratorGroup =
    group === 'administrators' || /관리자 그룹/.test(description);

  const groupAddition =
    /관리자 그룹에 추가|관리자 그룹 추가|관리자 그룹에 들어가|다시 관리자로 들어왔|계정\s*\d+개가 관리자 그룹에 추가/.test(description);

  const commandActivity = /관리자 명령|권한 명령|명령 실행/.test(description);
  const unfamiliarSource = /원격 주소|처음 보는 주소|요청 주소는 처음 봅니다/.test(description);
  const repeatedAddition = /다시 관리자로 들어왔|관리자 그룹에서 빠진 계정/.test(description);
  const multipleAccounts = getCount(alert) >= 2
    || /계정\s*[2-9]\d*개가 관리자 그룹에 추가/.test(description);

  const clearGroupAttack =
    administratorGroup
    && groupAddition
    && (
      unfamiliarSource
      || commandActivity
      || multipleAccounts
      || repeatedAddition
    );

  if (clearGroupAttack) {
    return result(
      'block',
      multipleAccounts || repeatedAddition ? 0.98 : 0.92,
      PATTERNS[0].name,
    );
  }

  const clearCommandAttack =
    commandActivity
    && (
      /방금 관리자가 된/.test(description)
      || unfamiliarSource
      || /다른 계정의 권한/.test(description)
      || /관리자 그룹에 들어가고 곧바로/.test(description)
      || /관리자 그룹 추가와 명령 실행/.test(description)
    );

  if (clearCommandAttack) {
    return result('block', 0.95, PATTERNS[1].name);
  }

  if (
    /세션이 관리자 권한으로 바뀌었/.test(description)
    && unfamiliarSource
  ) {
    return result('block', 0.95, PATTERNS[1].name);
  }

  const ambiguous = AMBIGUOUS_PATTERNS.find((pattern) =>
    pattern.matches(description)
  );

  if (ambiguous) {
    return result('alert', 0.62, ambiguous.name);
  }

  const offHours =
    /수업 시간 밖|업무 시간 밖|업무처럼 보이지 않는 시각/.test(description);

  const privilegeActivity =
    administratorGroup
    || commandActivity
    || /권한 상승|계정 종류|계정 유형|그룹에 추가|그룹.*만들어졌|그룹 설명.*바뀌/.test(description);

  if (PATTERNS[2] && offHours && privilegeActivity) {
    return result('alert', 0.6, PATTERNS[2].name);
  }

  return result(
    'record',
    0.08,
    '명확한 공격 또는 추가 확인이 필요한 권한 활동이 확인되지 않음',
  );
}
