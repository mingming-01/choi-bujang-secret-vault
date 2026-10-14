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

function decodeRequest(value) {
  let decoded = value.replace(/\+/g, ' ');
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function parseIpv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets;
}

function parseIpv6(value) {
  if (!value.includes(':') || value.includes('%')) return null;
  let input = value.toLowerCase();

  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4 = parseIpv4(input.slice(lastColon + 1));
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    input = `${input.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const compressionIndex = input.indexOf('::');
  if (compressionIndex !== -1 && input.indexOf('::', compressionIndex + 2) !== -1) return null;
  const hasCompression = compressionIndex !== -1;
  const leftText = hasCompression ? input.slice(0, compressionIndex) : input;
  const rightText = hasCompression ? input.slice(compressionIndex + 2) : '';
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...right];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;

  if (hasCompression) {
    if (groups.length >= 8) return null;
    const zeros = Array(8 - groups.length).fill('0');
    return [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16));
  }
  if (groups.length !== 8) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

function normalizeSource(source) {
  if (typeof source !== 'string') return '';
  const normalized = source.trim();
  const ipv4 = parseIpv4(normalized);
  if (ipv4) return `ipv4:${ipv4.join('.')}`;
  const ipv6 = parseIpv6(normalized);
  return ipv6 ? `ipv6:${ipv6.map((group) => group.toString(16).padStart(4, '0')).join(':')}` : '';
}

// Request pattern IDs intentionally match the standalone decide.mjs patterns.
// Fixture doc-* markers, descriptions and data.count are not attack evidence.
function getWebInjectionPatterns(alert) {
  const requestText = [
    alert?.data?.url,
    alert?.data?.uri,
    alert?.url,
    alert?.requestUrl,
    alert?.request,
  ]
    .filter((value) => typeof value === 'string')
    .map(decodeRequest)
    .join(' ');
  const patterns = [];
  if (/\bunion\s+(?:all\s+)?select\b|\bselect\s+[\w`'"*.,()+%\-\s]{1,100}\s+from\s+[\w`".]+|(?:\bor\b|\band\b)\s+['"]?[\w-]+['"]?\s*=\s*['"]?[\w-]+['"]?|['"]\s*(?:or|and)\b|--(?:\s|$)|\/\*/i.test(requestText)) {
    patterns.push('sql-injection');
  }
  if (/<\s*\/?\s*script\b[^>]*>/i.test(requestText)) patterns.push('script-tag');
  if (/(?:\.\.[/\\]){2,}/i.test(requestText)) patterns.push('path-traversal');
  return {
    sourceAddress: normalizeSource(alert?.sourceAddress ?? alert?.source ?? alert?.data?.srcip),
    patterns,
  };
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

  // Correlate distinct alerts by normalized source IP + one exact request pattern.
  // alert IDs, not data.count or description claims, establish distinct events.
  const correlationByAlert = new Map();
  if (moduleKey === 'web-injection') {
    const observations = [];
    const groups = new Map();
    const alertIdCounts = new Map();
    for (const alert of fixture.alerts) {
      const alertId = typeof alert?.id === 'string' ? alert.id.trim() : '';
      if (alertId) alertIdCounts.set(alertId, (alertIdCounts.get(alertId) ?? 0) + 1);
    }
    for (const alert of fixture.alerts) {
      const alertId = typeof alert?.id === 'string' ? alert.id.trim() : '';
      const evidence = getWebInjectionPatterns(alert);
      if (alertId && alertIdCounts.get(alertId) === 1 && evidence.sourceAddress && evidence.patterns.length === 1) {
        const patternId = evidence.patterns[0];
        const key = `${evidence.sourceAddress}\u0000${patternId}`;
        observations.push({ alert, sourceAddress: evidence.sourceAddress, patternId, key });
        if (!groups.has(key)) groups.set(key, new Map());
        groups.get(key).set(alertId, evidence);
      }
    }
    for (const observation of observations) {
      const distinctIds = [...groups.get(observation.key).keys()];
      if (distinctIds.length >= 2) {
        correlationByAlert.set(observation.alert, {
          sourceAddress: observation.sourceAddress,
          patternId: observation.patternId,
          alertIds: distinctIds,
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
      let input = alert;
      if (moduleKey === 'web-injection') {
        // Discard any fixture-provided correlation claim. Only evidence built
        // from this fixture's distinct alerts may be passed to decide().
        input = { ...alert, correlationEvidence: correlationByAlert.get(alert) };
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
