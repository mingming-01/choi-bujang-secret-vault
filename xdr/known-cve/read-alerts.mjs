import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 확인용 읽기 도구입니다. decide.mjs 는 이 파일을 불러오지 않습니다.
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SECRET = /(?:password|passwd|pwd|token|secret|api[_-]?key|authorization)\s*[=:]\s*\S+|\b[A-Za-z0-9+/_-]{32,}={0,2}\b/gi;

function redact(value) {
  return typeof value === 'string' ? value.replace(SECRET, '[REDACTED]') : String(value ?? '-');
}

const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'known-cve.json'), 'utf8'));
const alerts = Array.isArray(fixture.alerts) ? fixture.alerts : [];
const lines = alerts.map((alert) => [
  alert?.timestamp ?? '-',
  alert?.data?.srcip ?? '-',
  alert?.data?.srcuser ?? '-',
  alert?.rule?.level ?? '-',
  alert?.rule?.description ?? '-',
].map(redact).join(' | '));
lines.forEach((line) => console.log(line));
console.log(`경보 ${alerts.length}건, 출력 ${lines.length}줄`);
