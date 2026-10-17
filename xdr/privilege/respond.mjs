import { appendFile, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';

const EXPIRATION_MINUTES = 30;

const PATTERNS = [
  {
    id: 'administrator-group-addition',
    name: '일반 계정의 관리자 그룹 추가',
  },
  {
    id: 'unfamiliar-admin-command',
    name: '낯선 출발지 또는 권한 변경 직후의 관리자 명령',
  },
];

function normalizeIp(value) {
  if (typeof value !== 'string') return '';

  const input = value.trim();
  if (!input || /[\s/]/.test(input)) return '';

  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(input);
  const candidate = mapped ? mapped[1] : input;

  return isIP(candidate) ? candidate.toLowerCase() : '';
}

function getSource(alert) {
  for (const value of [
    alert?.sourceAddress,
    alert?.source,
    alert?.data?.srcip,
  ]) {
    const source = normalizeIp(value);
    if (source) return source;
  }

  return '';
}

function getExpiration() {
  const expiration = new Date(Date.now() + EXPIRATION_MINUTES * 60 * 1000);
  return Number.isFinite(expiration.getTime())
    ? expiration.toISOString()
    : '';
}

function getPatternId(reason) {
  if (typeof reason !== 'string') return '';

  const pattern = PATTERNS.find(({ name }) =>
    reason === name || reason.startsWith(`${name}:`)
  );

  return pattern?.id ?? '';
}

export async function respond({ root, decisions, alerts }) {
  const decisionList = Array.isArray(decisions) ? decisions : [];
  const alertList = Array.isArray(alerts) ? alerts : [];
  const alertById = new Map(
    alertList
      .filter((alert) => typeof alert?.id === 'string')
      .map((alert) => [alert.id, alert]),
  );

  const nonBlockSources = new Set();

  for (const decision of decisionList) {
    if (decision?.action === 'block') continue;

    const alert = alertById.get(decision?.alertId);
    const source = alert ? getSource(alert) : '';

    if (source) nonBlockSources.add(source);
  }

  const rules = [];
  const logLines = [];
  let skippedInvalidSource = 0;
  let skippedInvalidTimestamp = 0;
  let skippedMissingPattern = 0;
  let skippedNonBlockSource = 0;

  for (const decision of decisionList) {
    if (!['block', 'alert'].includes(decision?.action)) continue;

    const alert = alertById.get(decision.alertId);
    if (!alert) continue;

    const source = getSource(alert);
    let expiresAt = '';
    let patternId = '';
    let outcome = 'alert_only';

    if (decision.action === 'block') {
      if (decision.confidence < 0.85) {
        outcome = 'skipped_low_confidence';
      } else if (!source) {
        skippedInvalidSource += 1;
        outcome = 'skipped_invalid_source';
      } else if (nonBlockSources.has(source)) {
        skippedNonBlockSource += 1;
        outcome = 'skipped_source_has_non_block_event';
      } else {
        expiresAt = getExpiration();
        if (!expiresAt) {
          skippedInvalidTimestamp += 1;
          outcome = 'skipped_invalid_timestamp';
        } else {
          patternId = getPatternId(decision.reason);

          if (!patternId) {
            skippedMissingPattern += 1;
            outcome = 'skipped_missing_pattern_evidence';
          } else {
            rules.push({
              action: 'deny',
              moduleKey: 'privilege',
              source,
              expiresAt,
              sourceAlert: alert.id,
              patternId,
            });

            outcome = 'deny_candidate';
          }
        }
      }
    }

    const time = typeof alert.timestamp === 'string'
      ? Date.parse(alert.timestamp)
      : NaN;

    logLines.push(JSON.stringify({
      timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
      moduleKey: 'privilege',
      alertId: alert.id,
      action: decision.action,
      sourceAddress: source || null,
      expiresAt: expiresAt || null,
      patternId: patternId || null,
      outcome,
    }));
  }

  if (logLines.length > 0) {
    const logPath = join(root, 'xdr', 'alerts.log');
    let existing = '';

    try {
      existing = await readFile(logPath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }

    const seen = new Set();

    for (const line of existing.split(/\r?\n/)) {
      if (!line) continue;

      try {
        const entry = JSON.parse(line);

        if (
          entry?.moduleKey === 'privilege'
          && typeof entry.alertId === 'string'
          && typeof entry.action === 'string'
        ) {
          seen.add(entry.moduleKey + ':' + entry.alertId + ':' + entry.action);
        } else {
          seen.add(line);
        }
      } catch {
        seen.add(line);
      }
    }

    const fresh = logLines.filter((line) => {
      const entry = JSON.parse(line);
      const key = entry.moduleKey + ':' + entry.alertId + ':' + entry.action;

      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (fresh.length > 0) {
      const separator = existing !== '' && !/\r?\n$/.test(existing)
        ? '\n'
        : '';

      await appendFile(
        logPath,
        separator + fresh.join('\n') + '\n',
        'utf8',
      );
    }
  }

  return {
    rules,
    blocked: rules.length,
    normalBlocked: false,
    skippedInvalidSource,
    skippedInvalidTimestamp,
    skippedMissingPattern,
    skippedNonBlockSource,
  };
}
