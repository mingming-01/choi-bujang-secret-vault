const PATTERNS = [
  {
    id: 'administrator-group-addition',
    name: '일반 계정의 관리자 그룹 추가',
    condition: '일반 계정의 관리자 그룹 추가 또는 관리자 권한 재등록이 확인된다.',
    basis: 'T1078: 일반 계정에 관리자 권한이 부여된 정황을 확인한다.',
    matches: (description) =>
      /관리자 그룹(?:에 추가| 추가|에 들어가)|다시 관리자로 들어왔/.test(description)
      && !/관리자 그룹은 아닙니다/.test(description),
  },
  {
    id: 'unfamiliar-admin-command',
    name: '낯선 출발지 또는 권한 변경 직후의 관리자 명령',
    condition: '처음 보는 주소, 권한 상승 직후 또는 다른 계정의 권한을 이용한 관리자 명령이 확인된다.',
    basis: 'T1068 및 T1078: 권한 상승과 계정 오용 가능성을 보여 주는 구체적인 명령 실행 정황을 확인한다.',
    matches: (description) =>
      /방금 관리자가 된 .{0,40}관리자 명령을 실행|처음 보는 주소에서 관리자 명령을 실행|관리자 그룹에 들어가고 곧바로 권한 명령을 실행|다른 계정의 권한으로 관리자 명령을 실행|관리자 그룹 추가와 명령 실행이 같이|세션이 관리자 권한으로 바뀌었고 요청 주소는 처음 봅니다/.test(description),
  },
  {
    id: 'off-hours-privilege-use',
    name: '업무 시간 밖의 권한 사용',
    condition: '경보 설명에 업무 또는 수업의 정상 시간 밖에서 권한 사용이 발생했다고 명시된다.',
    basis: 'T1078: 비정상적인 시간대의 권한 사용은 계정 오용 가능성을 살펴볼 보조 신호다.',
    matches: (description) =>
      /수업 시간 밖|업무 시간 밖|업무처럼 보이지 않는 시각/.test(description),
  },
];

function getDescription(alert) {
  return typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
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
  const groupPattern = PATTERNS[0];
  const commandPattern = PATTERNS[1];
  const offHoursPattern = PATTERNS[2];

  const groupAddition = groupPattern.matches(description);
  const unfamiliarCommand = commandPattern.matches(description);
  const offHours = offHoursPattern.matches(description);

  const multipleAccounts =
    /계정\s*\d+개가 관리자 그룹에 추가/.test(description);
  const readdedAdministrator =
    /다시 관리자로 들어왔/.test(description);
  const unfamiliarSource =
    /원격 주소|처음 보는 주소|요청 주소는 처음 봅니다/.test(description);

  if (
    groupAddition
    && (
      unfamiliarSource
      || multipleAccounts
      || readdedAdministrator
      || unfamiliarCommand
      || offHours
    )
  ) {
    const confidence = multipleAccounts || readdedAdministrator
      ? 0.98
      : unfamiliarCommand || offHours
        ? 0.97
        : 0.92;

    return result('block', confidence, groupPattern.name);
  }

  if (unfamiliarCommand) {
    return result('block', 0.95, commandPattern.name);
  }

  const ambiguousSignals = [
    {
      matches: /권한 상승 창이 한 번 뜨고 취소됐습니다/,
      reason: '권한 상승 요청이 취소되어 실제 권한 변경은 확인되지 않음',
    },
    {
      matches: /평소 주소에서 관리자 명령이 한 번 실행됐습니다/,
      reason: '평소 주소에서 발생한 단일 관리자 명령으로 추가 확인 필요',
    },
    {
      matches: /권한 상승이 1건 있고 이어서 명령은 없습니다/,
      reason: '단일 권한 상승 정황이며 후속 명령은 확인되지 않음',
    },
    {
      matches: /관리자 명령이 실패 1건으로 끝났습니다/,
      reason: '관리자 명령 실패 1건으로 실제 권한 상승은 확인되지 않음',
    },
  ];

  const ambiguous = ambiguousSignals.find((pattern) =>
    pattern.matches.test(description)
  );

  if (ambiguous) {
    return result('alert', 0.62, ambiguous.reason);
  }

  if (offHours) {
    return result('alert', 0.62, `${offHoursPattern.name}: 추가 확인 필요`);
  }

  return result(
    'record',
    0.08,
    '명확한 권한 상승 또는 의심스러운 권한 사용 증거가 확인되지 않음',
  );
}
