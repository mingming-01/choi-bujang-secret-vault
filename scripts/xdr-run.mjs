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

  // 순수 판정 함수는 이벤트 하나씩 받습니다. web-injection만 먼저 동일한 판정 함수를
  // 분류 모드로 명시된 단일 패턴 후보를 찾고, 유효한 srcip와 패턴별 이벤트 수를 집계합니다.
  // 원본 경보를 수정하지 않으며, 집계값은 최종 판정 호출에만 전달됩니다.
  const sourceRepeatCounts = new Map();
  if (moduleKey === 'web-injection') {
    for (const alert of fixture.alerts) {
      try {
        const candidate = await loaded.decide(alert, { classifyOnly: true });
        const source = alert?.data?.srcip;
        if (
          isDecision(candidate)
          && candidate.reason.startsWith('분류용 후보:')
          && typeof source === 'string'
          && source.trim() !== ''
        ) {
          const patternName = candidate.reason.slice('분류용 후보:'.length).trim();
          const countsByPattern = sourceRepeatCounts.get(source.trim()) ?? new Map();
          countsByPattern.set(patternName, (countsByPattern.get(patternName) ?? 0) + 1);
          sourceRepeatCounts.set(source.trim(), countsByPattern);
        }
      } catch {
        // 최종 판정 호출이 기존처럼 오류를 record 처리하므로 사전 집계는 건너뜁니다.
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
      const source = alert?.data?.srcip;
      const context = moduleKey === 'web-injection'
        && typeof source === 'string'
        && source.trim() !== ''
        ? { sourceRepeatCounts: Object.fromEntries(sourceRepeatCounts.get(source.trim()) ?? []) }
        : undefined;
      const out = context
        ? await loaded.decide(alert, context)
        : await loaded.decide(alert);
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
