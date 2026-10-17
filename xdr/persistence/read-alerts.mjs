import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const fixturePath = join(root, 'xdr', 'fixtures', 'persistence.json');

const SECRET_ASSIGNMENT =
  /\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie)\b\s*([=:])\s*([^\s,;&|]+)/gi;
const BEARER_TOKEN = /\bBearer\s+\S+/gi;

function safeText(value) {
  return String(value ?? '-')
    .replace(SECRET_ASSIGNMENT, '$1$2[REDACTED]')
    .replace(BEARER_TOKEN, 'Bearer [REDACTED]')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|');
}

const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const alerts = Array.isArray(fixture.alerts) ? fixture.alerts : [];

const lines = alerts.map((alert) => [
  alert?.timestamp,
  alert?.data?.srcip,
  alert?.data?.srcuser,
  alert?.rule?.level,
  alert?.rule?.description,
].map(safeText).join(' | '));

for (const line of lines) {
  console.log(line);
}

console.log(`경보 ${alerts.length}건, 출력 ${lines.length}줄`);
