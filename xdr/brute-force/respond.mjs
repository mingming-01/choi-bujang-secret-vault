import { appendFile } from 'node:fs/promises';
import { join } from 'node:path';

const EXPIRATION_MINUTES = 30;

function getExpiration(timestamp) {
  const time = new Date(timestamp).getTime();

  if (!Number.isFinite(time)) {
    return '';
  }

  return new Date(time + EXPIRATION_MINUTES * 60 * 1000).toISOString();
}

export async function respond({ root, decisions, alerts }) {
  const blockCandidates = decisions.filter((decision) => decision.action === 'block');
  const rules = [];
  const logLines = [];

  for (const decision of blockCandidates) {
    const alert = alerts.find((item) => item.id === decision.alertId);

    if (!alert) {
      continue;
    }

    const expiration = getExpiration(alert.timestamp);

    if (!expiration) {
      continue;
    }

    const rule = {
      action: 'deny',
      source: alert.data?.srcip ?? '',
      expiresAt: expiration,
      sourceAlert: alert.id,
    };

    rules.push(rule);

    logLines.push(
      `${alert.timestamp} alert=${alert.id} action=deny source=${rule.source} expiresAt=${expiration}`,
    );
  }

  const logPath = join(root, 'xdr', 'alerts.log');

  if (logLines.length > 0) {
    await appendFile(logPath, `${logLines.join('\n')}\n`, 'utf8');
  }

  return {
    rules,
    blocked: rules.length,
    normalBlocked: false,
  };
}