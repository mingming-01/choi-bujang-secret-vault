import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function redact(value) {
  if (typeof value !== 'string') {
    return value ?? '';
  }

  return value
    .replace(
      /\b(password|passwd|token|secret|api[_ -]?key|credential|authorization|private[_ -]?key)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
      '$1$2[REDACTED]',
    )
    .replace(
      /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
      'Bearer [REDACTED]',
    )
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
      '[REDACTED]',
    );
}

function extractAlert(alert) {
  return {
    timestamp: redact(alert?.timestamp),
    sourceAddress: redact(alert?.data?.srcip),
    account: redact(alert?.data?.srcuser),
    ruleLevel: alert?.rule?.level ?? null,
    description: redact(alert?.rule?.description),
  };
}

export async function readAlerts(root) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'exfiltration.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'exfiltration'
    || !Array.isArray(fixture.alerts)
  ) {
    throw new Error('자료 유출 경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map(extractAlert);
}

const root = fileURLToPath(new URL('../..', import.meta.url));
const isDirectRun = process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  try {
    const alerts = await readAlerts(root);

    for (const alert of alerts) {
      console.log(JSON.stringify(alert));
    }

    console.log(`경보 건수: ${alerts.length}`);
    console.log(`추출한 줄 수: ${alerts.length}`);
  } catch {
    console.error('자료 유출 경보를 읽지 못했습니다.');
    process.exitCode = 1;
  }
}
