import { appendFile, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';

const EXPIRATION_MINUTES = 30;

const PATTERN_IDS = {
  'unsigned-new-service': 'unsigned-new-service',
  'unsigned-service-burst': 'unsigned-new-service',
  'unsigned-service-update': 'unsigned-new-service',
  'persistent-unknown-service': 'unsigned-new-service',
  'unusual-scheduled-task': 'unusual-scheduled-task',
  'random-scheduled-task': 'unusual-scheduled-task',
  'startup-folder-change': 'startup-folder-change',
  'shared-persistence-file': 'startup-folder-change',
};

function getExpiration(timestamp) {
  if (typeof timestamp !== 'string' || timestamp.trim() === '') return '';

  const time = Date.parse(timestamp);
  if (!Number.isFinite(time)) return '';

  return new Date(time + EXPIRATION_MINUTES * 60 * 1000).toISOString();
}

function normalizeIp(value) {
  if (typeof value !== 'string') return '';

  const input = value.trim();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(input);
  const candidate = mapped ? mapped[1] : input;

  return isIP(candidate) ? candidate.toLowerCase() : '';
}

function getValidSource(alert) {
  for (const candidate of [
    alert?.sourceAddress,
    alert?.source,
    alert?.data?.srcip,
  ]) {
    const source = normalizeIp(candidate);
    if (source) return source;
  }

  return '';
}

function getPatternId(decision) {
  if (typeof decision?.reason !== 'string') return '';

  const separator = decision.reason.indexOf(':');
  const id = separator < 0
    ? decision.reason
    : decision.reason.slice(0, separator);

  return PATTERN_IDS[id] || '';
}

export async function respond({ root, decisions, alerts }) {
  const decisionList = Array.isArray(decisions) ? decisions : [];
  const alertList = Array.isArray(alerts) ? alerts : [];

  const rules = [];
  const logLines = [];
  let skippedInvalidTimestamp = 0;
  let skippedInvalidSource = 0;

  for (const decision of decisionList) {
    if (!['block', 'alert'].includes(decision?.action)) continue;

    const alertId = typeof decision.alertId === 'string'
      ? decision.alertId
      : '';

    const alert = alertList.find((item) => item?.id === alertId);
    if (!alert) continue;

    const source = getValidSource(alert);
    let expiration = '';
    let patternId = '';
    let outcome = 'alert_only';

    if (decision.action === 'block') {
      if (!source) {
        skippedInvalidSource += 1;
        outcome = 'skipped_invalid_source';
      } else {
        expiration = getExpiration(alert.timestamp);

        if (!expiration) {
          skippedInvalidTimestamp += 1;
          outcome = 'skipped_invalid_timestamp';
        } else {
          patternId = getPatternId(decision);

          if (!patternId) {
            outcome = 'skipped_missing_pattern_evidence';
          } else {
            rules.push({
              action: 'deny',
              moduleKey: 'persistence',
              source,
              expiresAt: expiration,
              sourceAlert: alert.id,
              patternId,
            });

            outcome = 'deny_candidate';
          }
        }
      }
    }

    const parsedTimestamp = typeof alert.timestamp === 'string'
      ? Date.parse(alert.timestamp)
      : NaN;

    logLines.push(JSON.stringify({
      timestamp: Number.isFinite(parsedTimestamp)
        ? new Date(parsedTimestamp).toISOString()
        : null,
      moduleKey: 'persistence',
      alertId: alert.id,
      action: decision.action,
      sourceAddress: source || null,
      expiresAt: expiration || null,
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

    const seen = new Set(existing.split(/\r?\n/));
    const fresh = logLines.filter((line) => {
      if (seen.has(line)) return false;
      seen.add(line);
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
    skippedInvalidTimestamp,
    skippedInvalidSource,
  };
}
