import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODULE_KEYS = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const ACTIONS = new Set(['block', 'alert', 'record']);

export function isDecision(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && typeof value.confidence === 'number'
    && Number.isFinite(value.confidence)
    && value.confidence >= 0
    && value.confidence <= 1
    && typeof value.reason === 'string';
}

export async function runXdr({ root, moduleKey, writeError = (line) => console.error(line) }) {
  if (!MODULE_KEYS.includes(moduleKey)) {
    throw new Error('moduleKey 가 없습니다. brute-force, web-injection, known-cve, persistence, privilege, exfiltration 중 하나를 넣습니다.');
  }
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', `${moduleKey}.json`), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== moduleKey || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const loaded = await import(pathToFileURL(join(root, 'xdr', moduleKey, 'decide.mjs')).href);
  if (typeof loaded.decide !== 'function') throw new Error('decide 함수를 내보내지 않았습니다.');

  // Correlate only independently observed request patterns from distinct fixture alerts.
  // Descriptions, data.count, and generic runner-only classifier flags are never evidence.
  const repeatByAlert = new Map();
  if (moduleKey === 'web-injection') {
    if (typeof loaded.analyzeAlert !== 'function') {
      throw new Error('web-injection decide.mjs는 analyzeAlert(alert)를 내보내야 합니다.');
    }
    const groupCounts = new Map();
    const observations = [];
    for (const alert of fixture.alerts) {
      try {
        const evidence = loaded.analyzeAlert(alert);
        if (
          typeof evidence?.sourceAddress === 'string'
          && evidence.sourceAddress !== ''
          && Array.isArray(evidence.patterns)
          && evidence.patterns.length === 1
          && typeof evidence.patterns[0] === 'string'
        ) {
          const patternId = evidence.patterns[0];
          const key = `${evidence.sourceAddress}\u0000${patternId}`;
          groupCounts.set(key, (groupCounts.get(key) ?? 0) + 1);
          observations.push({ alert, sourceAddress: evidence.sourceAddress, patternId, key });
        }
      } catch {
        // The final decide call handles malformed inputs as record.
      }
    }
    for (const observation of observations) {
      const occurrences = groupCounts.get(observation.key) ?? 0;
      if (occurrences >= 2) {
        repeatByAlert.set(observation.alert, {
          sourceAddress: observation.sourceAddress,
          patternId: observation.patternId,
          occurrences,
        });
      }
    }
  }

  const decisions = [];
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const alertId = alert && typeof alert.id === 'string' ? alert.id : '';
    let action = 'record';
    let confidence = 0;
    let reason = '반환 형식이 아닙니다';
    try {
      const correlationEvidence = repeatByAlert.get(alert);
      const input = correlationEvidence ? { ...alert, correlationEvidence } : alert;
      const out = await loaded.decide(input);
      if (isDecision(out)) {
        action = out.action;
        confidence = out.confidence;
        reason = out.reason;
      } else {
        writeError(`형식 오류: ${alertId || '(id 없음)'}`);
      }
    } catch {
      writeError(`형식 오류: ${alertId || '(id 없음)'}`);
    }
    decisions.push({ alertId, action, confidence, reason });
    counts[action] += 1;
  }

  const result = { schema: 'aleph.xdr.result.v1', moduleKey, decisions, counts };
  const outDir = join(root, 'xdr', moduleKey);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');

  if (moduleKey === 'brute-force' || moduleKey === 'web-injection') {
    const respondPath = join(root, 'xdr', moduleKey, 'respond.mjs');

    try {
      await access(respondPath);
    } catch {
      return result;
    }

    const responder = await import(pathToFileURL(respondPath).href);

    if (typeof responder.respond !== 'function') {
      throw new Error('respond 함수를 내보내지 않았습니다.');
    }

    await responder.respond({
      root,
      decisions,
      alerts: fixture.alerts,
    });
  }

  return result;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    await runXdr({ root, moduleKey: process.argv[2] });
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
