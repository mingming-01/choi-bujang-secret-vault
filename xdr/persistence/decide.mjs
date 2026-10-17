function getDescription(alert) {
  return typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
}

function getPath(alert) {
  return typeof alert?.data?.path === 'string'
    ? alert.data.path
    : '';
}

function hasMitre(alert, technique) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.includes(technique);
}

function hasPersistenceTechnique(alert) {
  return hasMitre(alert, 'T1543') || hasMitre(alert, 'T1053');
}

function isTempPath(path) {
  return /[\\/]temp[\\/]/i.test(path);
}

function isStartupPath(path) {
  return /[\\/]startup[\\/]/i.test(path);
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

const CLEAR_PATTERNS = [
  {
    id: 'unsigned-new-service',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1543')
        && /서명 없는 새 서비스가 임시 폴더의 실행 파일을 가리킵니다/.test(description)
        && isTempPath(path);
    },
    reason: 'unsigned service points to a temporary executable',
  },
  {
    id: 'unusual-scheduled-task',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1053')
        && /처음 보는 예약 작업이 임시 폴더의 프로그램을 수업 시간 밖에 실행합니다/.test(description)
        && isTempPath(path);
    },
    reason: 'unfamiliar scheduled task runs a temporary executable outside class time',
  },
  {
    id: 'startup-folder-change',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1543')
        && /시작 폴더에 평소 목록에 없는 프로그램이 추가됐습니다/.test(description)
        && isStartupPath(path);
    },
    reason: 'unrecognized program added to the startup folder',
  },
  {
    id: 'unsigned-service-burst',
    matches: (alert) => {
      return hasMitre(alert, 'T1543')
        && /원격 주소에서 서명 없는 서비스 등록이 연속으로 3건입니다/.test(getDescription(alert))
        && getCount(alert) >= 3;
    },
    reason: 'repeated unsigned service registrations with a matching event count',
  },
  {
    id: 'random-scheduled-task',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1053')
        && /예약 작업 이름이 임의 문자열이고 실행 파일이 임시 폴더에 있습니다/.test(description)
        && isTempPath(path);
    },
    reason: 'random-looking scheduled task launches a temporary executable',
  },
  {
    id: 'unsigned-service-update',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1543')
        && /서비스 실행 파일이 바뀌었고 서명이 없습니다/.test(description)
        && isTempPath(path);
    },
    reason: 'service executable changed and is reported unsigned',
  },
  {
    id: 'shared-persistence-file',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1543')
        && hasMitre(alert, 'T1053')
        && /시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킵니다/.test(description)
        && isTempPath(path);
    },
    reason: 'startup entry and scheduled task point to the same temporary executable',
  },
  {
    id: 'persistent-unknown-service',
    matches: (alert) => {
      const description = getDescription(alert);
      const path = getPath(alert);

      return hasMitre(alert, 'T1543')
        && /평소 목록에 없는 서비스가 다시 켜도 남도록 등록됐습니다/.test(description)
        && isTempPath(path);
    },
    reason: 'unrecognized service is configured to persist after restart',
  },
];

const AMBIGUOUS_PATTERNS = [
  {
    id: 'unconfirmed-signature',
    matches: (alert) => {
      return hasPersistenceTechnique(alert)
        && /서명은 확인되지 않았습니다|서명은 아직 모릅니다/.test(getDescription(alert));
    },
    reason: 'signature is unconfirmed and additional evidence is needed',
  },
  {
    id: 'single-or-benign-looking-change',
    matches: (alert) => {
      const description = getDescription(alert);

      return hasPersistenceTechnique(alert) && [
        /서비스 설명만 한 번 바뀌었습니다/,
        /예약 작업이 하나 있고 실행 시각은 수업 시간입니다/,
        /임시 폴더에 실행 파일이 하나 생겼습니다\. 서비스 등록은 없습니다/,
        /시작 폴더 변경이 1건입니다\. 이어서 실행된 기록은 없습니다/,
        /예약 작업 이름이 수업 과제와 비슷하고/,
        /서비스가 한 번 멈췄다가 같은 파일로 다시 시작됐습니다/,
      ].some((pattern) => pattern.test(description));
    },
    reason: 'single change or weak signal needs further review',
  },
];

export function decide(alert) {
  for (const pattern of CLEAR_PATTERNS) {
    if (pattern.matches(alert)) {
      return result('block', 0.95, `${pattern.id}: ${pattern.reason}`);
    }
  }

  for (const pattern of AMBIGUOUS_PATTERNS) {
    if (pattern.matches(alert)) {
      return result('alert', 0.65, `${pattern.id}: ${pattern.reason}`);
    }
  }

  const level = alert?.rule?.level;
  if (
    hasPersistenceTechnique(alert)
    && Number.isFinite(level)
    && level >= 8
  ) {
    return result(
      'alert',
      0.55,
      'elevated-level: persistence-related event needs further review',
    );
  }

  return result(
    'record',
    0.08,
    'normal-or-unsupported: no clear persistence evidence',
  );
}
