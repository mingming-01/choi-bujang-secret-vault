import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODULE_KEYS = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const ACTIONS = new Set(['block', 'alert', 'record']);
const RUNNER_EVIDENCE_KEY = '__xdrRunnerRepeatEvidence';
const RUNNER_CLASSIFY_KEY = '__xdrRunnerClassifyOnly';

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

  // Repetition is counted only from actual fixture alerts sharing a source and a single pattern.
  // Neither data.count nor repetition figures mentioned in descriptions enter this cross-alert count.
  const sourceRepeatCounts = new Map();
  const patternByAlertId = new Map();
  if (moduleKey === 'web-injection') {
    for (const alert of fixture.alerts) {
      try {
        const candidate = await loaded.decide({ ...alert, [RUNNER_CLASSIFY_KEY]: true });
        const source = alert?.data?.srcip;
        if (
          isDecision(candidate)
          && candidate.reason.startsWith('분류용 후보:')
          && typeof source === 'string'
          && source.trim() !== ''
        ) {
          const patternName = candidate.reason.slice('분류용 후보:'.length).trim();
          const normalizedSource = source.trim();
          const countsByPattern = sourceRepeatCounts.get(normalizedSource) ?? new Map();
          countsByPattern.set(patternName, (countsByPattern.get(patternName) ?? 0) + 1);
          sourceRepeatCounts.set(normalizedSource, countsByPattern);
          patternByAlertId.set(alert?.id, { source: normalizedSource, patternName });
        }
      } catch {
        // Final call handles malformed decisions as record, so pre-aggregation may be skipped.
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
      let input = alert;
      if (moduleKey === 'web-injection') {
        const candidate = patternByAlertId.get(alertId);
        const count = candidate
          ? sourceRepeatCounts.get(candidate.source)?.get(candidate.patternName) ?? 0
          : 0;
        const source = alert?.data?.srcip;
        if (candidate && count >= 2 && typeof source === 'string' && source.trim() === candidate.source) {
          input = {
            ...alert,
            [RUNNER_EVIDENCE_KEY]: { ...candidate, count },
          };
        }
      }
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
