import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function extractAlert(alert) {
  const extracted = {
    timestamp: typeof alert?.timestamp === 'string' ? alert.timestamp : null,
    sourceAddress: typeof alert?.data?.srcip === 'string' ? alert.data.srcip : null,
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: typeof alert?.rule?.description === 'string' ? alert.rule.description : '',
  };

  // 계정 필드가 실제 있는 경우에만 복사하고, 누락된 계정은 만들지 않습니다.
  if (typeof alert?.data?.srcuser === 'string') {
    extracted.account = alert.data.srcuser;
  }

  return extracted;
}

export async function readAlerts(root) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'web-injection.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'web-injection'
    || !Array.isArray(fixture.alerts)
  ) {
    throw new Error('web-injection 경보 묶음 형식이 아닙니다.');
  }

  // 원본 경보 전체를 출력하지 않고 지정된 다섯 필드만 반환합니다.
  return fixture.alerts.map(extractAlert);
}

const projectRoot = fileURLToPath(new URL('../..', import.meta.url));
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    const alerts = await readAlerts(projectRoot);
    console.log(JSON.stringify(alerts, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : '경보 읽기 오류');
    process.exitCode = 1;
  }
}
