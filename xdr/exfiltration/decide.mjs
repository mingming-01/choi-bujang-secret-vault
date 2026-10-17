const PATTERNS = [
  {
    id: 'large-unfamiliar-destination-transfer',
    name: '처음 보는 목적지로 대용량 전송',
    condition: '처음 보는 목적지라는 신호와 함께 짧은 시간에 많은 자료가 전송되거나 대용량 전송이 반복된다.',
    basis: 'MITRE ATT&CK T1041: 공격자는 기존 명령·제어(C2) 통로를 통해 자료를 반출할 수 있다.',
  },
  {
    id: 'off-hours-archive-exfiltration',
    name: '업무 시간 밖 압축 파일 반출',
    condition: '업무 또는 수업 시간 밖이라는 신호와 압축 파일의 외부 전송 정황이 함께 나타난다.',
    basis: 'MITRE ATT&CK T1048: 공격자는 기존 C2 통로와 다른 네트워크 프로토콜을 이용해 자료를 반출할 수 있다.',
  },
];

const LARGE_TRANSFER_BYTES = 50_000_000;

function numberValue(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return value;
  }

  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    return Number(value.trim());
  }

  return 0;
}

function makeDecision(confidence, reason) {
  const action = confidence >= 0.85
    ? 'block'
    : confidence >= 0.5
      ? 'alert'
      : 'record';

  return { action, confidence, reason };
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const data = alert?.data ?? {};

  const bytes = numberValue(data.bytes);
  const files = numberValue(data.files);
  const count = numberValue(data.count);
  const destination = typeof data.dstip === 'string'
    ? data.dstip.trim()
    : '';

  const unfamiliarDestination =
    /처음 보는 목적지|처음 보는 주소|평소와 다른 주소|낯선 목적지|낯선 주소/.test(description);
  const offHours =
    /수업 시간 밖|업무 시간 밖|근무 시간 밖/.test(description);
  const archive = /압축 파일/.test(description);
  const repeatedTransfer = count >= 8
    || /대용량 전송이\s*\d+번 반복|전송이\s*\d+번/.test(description);
  const manyFiles = files >= 50;
  const unusualPort = /쓰지 않던 포트|평소에 쓰지 않던 포트/.test(description);
  const massExport = /자료실 전체|자료\s*\d+건이 한 번에|외부 주소로.*복사/.test(description);
  const commandChannel = /명령 통로/.test(description);

  const hasOutboundTransfer = destination !== '' && bytes > 0;
  const largeTransfer = bytes >= LARGE_TRANSFER_BYTES;

  const offHoursArchive =
    offHours && archive && hasOutboundTransfer;

  if (offHoursArchive && largeTransfer) {
    return makeDecision(0.98, PATTERNS[1].name);
  }

  const strongAnomaly = unfamiliarDestination
    || repeatedTransfer
    || manyFiles
    || unusualPort
    || massExport
    || commandChannel
    || offHours;

  if (largeTransfer && hasOutboundTransfer && strongAnomaly) {
    return makeDecision(0.92, PATTERNS[0].name);
  }

  const ambiguousSignal = unfamiliarDestination
    || /중간 크기 파일|전송량.*평소보다.*높|압축 파일/.test(description)
    || /자료\s*\d+건.*전송|백업처럼 보이는 전송/.test(description)
    || /파일 수.*늘|전송이 실패|명령 통로|일부만.*다른 주소/.test(description)
    || offHoursArchive;

  if (ambiguousSignal) {
    const reason = offHoursArchive
      ? PATTERNS[1].name
      : PATTERNS[0].name;

    return makeDecision(0.62, reason);
  }

  return makeDecision(0.08, '유출 패턴 근거 없음');
}
