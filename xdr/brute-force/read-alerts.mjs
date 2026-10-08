import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

function extractAlert(alert) {
  return {
    timestamp: alert?.timestamp ?? '',
    sourceAddress: alert?.data?.srcip ?? '',
    account: alert?.data?.srcuser ?? '',
    ruleLevel: alert?.rule?.level ?? null,
    description: alert?.rule?.description ?? '',
  };
}

export async function readAlerts(root) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'brute-force.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'brute-force'
    || !Array.isArray(fixture.alerts)
  ) {
    throw new Error('brute-force 경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map(extractAlert);
}

const root = fileURLToPath(new URL("../..", import.meta.url));

try {
  const alerts = await readAlerts(root);
  console.log(JSON.stringify(alerts, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : "실행 오류");
  process.exitCode = 1;
}
