import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runXdr } from './xdr-run.mjs';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const temporaryRoot = await mkdtemp(join(tmpdir(), 'web-injection-repeat-'));
try {
  const moduleDir = join(temporaryRoot, 'xdr', 'web-injection');
  const fixtureDir = join(temporaryRoot, 'xdr', 'fixtures');
  await mkdir(moduleDir, { recursive: true });
  await mkdir(fixtureDir, { recursive: true });
  await writeFile(
    join(moduleDir, 'decide.mjs'),
    await readFile(join(projectRoot, 'xdr', 'web-injection', 'decide.mjs'), 'utf8'),
    'utf8',
  );
  await writeFile(
    join(moduleDir, 'respond.mjs'),
    await readFile(join(projectRoot, 'xdr', 'web-injection', 'respond.mjs'), 'utf8'),
    'utf8',
  );

  const fixture = {
    schema: 'aleph.xdr.fixture.v1',
    moduleKey: 'web-injection',
    alerts: [
      { id: 'rep-sql-a', data: { srcip: '203.0.113.200', url: '/search?q=union+select+name+from+users', count: '90' } },
      { id: 'rep-sql-b', data: { srcip: '203.0.113.200', url: '/search?q=union+select+email+from+accounts', count: '90' } },
      { id: 'different-pattern', data: { srcip: '203.0.113.200', url: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', count: '90' } },
      { id: 'different-source', data: { srcip: '198.51.100.200', url: '/search?q=union+select+name+from+users', count: '90' } },
      { id: 'normal', data: { srcip: '192.0.2.200', url: '/search?q=select-course', count: '90' } },
    ],
  };
  await writeFile(join(fixtureDir, 'web-injection.json'), `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

  const result = await runXdr({ root: temporaryRoot, moduleKey: 'web-injection', writeError: (line) => { throw new Error(line); } });
  const actualById = new Map(result.decisions.map((decision) => [decision.alertId, decision]));
  assert.equal(actualById.get('rep-sql-a')?.action, 'block', 'same source and repeated single SQL pattern is blockable');
  assert.equal(actualById.get('rep-sql-b')?.action, 'block', 'same-source SQL peer is also blockable');
  assert.equal(actualById.get('different-pattern')?.action, 'alert', 'different pattern does not share SQL repeat evidence');
  assert.equal(actualById.get('different-source')?.action, 'alert', 'different source does not share repeat evidence');
  assert.equal(actualById.get('normal')?.action, 'record', 'normal event remains record');
  assert.deepEqual(result.counts, { block: 2, alert: 2, record: 1 });
  assert.equal(result.decisions.filter((decision) => decision.alertId === 'normal' && decision.action === 'block').length, 0);

  console.log('실행기 반복 집계 단위 테스트 통과: data.count 무시, 같은 출발지·동일 패턴 반복만 공유');
  for (const decision of result.decisions) console.log(`${decision.alertId} | ${decision.action}`);
  console.log(`집계: block ${result.counts.block} / alert ${result.counts.alert} / record ${result.counts.record}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
