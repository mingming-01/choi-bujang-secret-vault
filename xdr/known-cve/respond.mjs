import { appendFile, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';

const EXPIRATION_MINUTES = 30;
const PATTERN_IDS = ['jndi-lookup'];

function getExpiration(timestamp) {
  if (typeof timestamp !== 'string' || timestamp.trim() === '') return '';
  const time = Date.parse(timestamp);
  if (!Number.isFinite(time)) return '';
  const expiration = new Date(time + EXPIRATION_MINUTES * 60 * 1000);
  return Number.isFinite(expiration.getTime()) ? expiration.toISOString() : '';
}

function normalizeIp(value) {
  if (typeof value !== 'string') return '';
  const ip = value.trim();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const candidate = mapped ? mapped[1] : ip;
  return isIP(candidate) ? candidate.toLowerCase() : '';
}

function getValidSource(alert) {
  for (const candidate of [alert?.sourceAddress, alert?.source, alert?.data?.srcip]) {
    const source = normalizeIp(candidate);
    if (source) return source;
  }
  return '';
}

export async function respond({ root, decisions, alerts }) {
  const decisionList = Array.isArray(decisions) ? decisions : [];
  const alertList = Array.isArray(alerts) ? alerts : [];
  const rules = [];
  const logLines = [];
  let skippedInvalidTimestamp = 0;
  let skippedInvalidSource = 0;

  for (const decision of decisionList) {
    const alertId = typeof decision?.alertId === 'string' ? decision.alertId : '';
    const alert = alertList.find((item) => item?.id === alertId);
    if (!alert || !['alert', 'block'].includes(decision?.action)) continue;
    const source = getValidSource(alert);

    let outcome = 'alert_only';
    let expiration = '';
    let patternId = '';
    if (decision.action === 'block') {
      if (alert?.data?.srcuser) {
        outcome = 'skipped_authenticated_user';
      } else if (!source) {
        skippedInvalidSource += 1;
        outcome = 'skipped_invalid_source';
      } else {
        expiration = getExpiration(alert.timestamp);
        if (!expiration) {
          skippedInvalidTimestamp += 1;
          outcome = 'skipped_invalid_timestamp';
        } else {
          patternId = PATTERN_IDS.find((id) => typeof decision.reason === 'string' && decision.reason.startsWith(id + ':')) ?? '';
          if (!patternId) {
            outcome = 'skipped_missing_pattern_evidence';
          } else {
            rules.push({ action: 'deny', source, expiresAt: expiration, sourceAlert: alert.id, patternId });
            outcome = 'deny_candidate';
          }
        }
      }
    }

    const parsed = typeof alert.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
    logLines.push(JSON.stringify({
      timestamp: Number.isFinite(parsed) ? new Date(parsed).toISOString() : null,
      moduleKey: 'known-cve',
      alertId: typeof alert.id === 'string' ? alert.id.slice(0, 200) : null,
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
      const separator = existing !== '' && !/\r?\n$/.test(existing) ? '\n' : '';
      await appendFile(logPath, separator + fresh.join('\n') + '\n', 'utf8');
    }
  }

  return { rules, blocked: rules.length, normalBlocked: false, skippedInvalidTimestamp, skippedInvalidSource };
}
