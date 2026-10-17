import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const SECRET_ASSIGNMENT =
  /\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie)\b\s*([=:])\s*([^\s,;&|]+)/gi;
const BEARER_TOKEN = /\bBearer\s+\S+/gi;
const LONG_TOKEN = /\b[A-Za-z0-9][A-Za-z0-9._~+/=-]{31,}\b/g;

function safeText(value) {
  return String(value ?? '-')
    .replace(SECRET_ASSIGNMENT, '$1$2[REDACTED]')
    .replace(BEARER_TOKEN, 'Bearer [REDACTED]')
    .replace(LONG_TOKEN, '[REDACTED]')
    .replace(/[\r\n\t|]/g, ' ');
}

function extractAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: safeText(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  };
}

export async function readAlerts(root) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'privilege.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'privilege'
    || !Array.isArray(fixture.alerts)
  ) {
    throw new Error('privilege 경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map(extractAlert);
}

const currentFile = fileURLToPath(import.meta.url);
const projectRoot = join(dirname(currentFile), '..', '..');
const isMain = process.argv[1]
  && resolve(process.argv[1]) === resolve(currentFile);

if (isMain) {
  try {
    const alerts = await readAlerts(projectRoot);

    for (const alert of alerts) {
      console.log([
        alert.timestamp,
        alert.sourceAddress,
        alert.account,
        alert.ruleLevel,
        alert.description,
      ].join(' | '));
    }

    console.log(`경보 ${alerts.length}건, 추출 ${alerts.length}줄`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : '경보 읽기 오류');
    process.exitCode = 1;
  }
}
