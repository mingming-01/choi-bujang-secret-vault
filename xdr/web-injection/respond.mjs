import { appendFile } from 'node:fs/promises';
import { join } from 'node:path';

const EXPIRATION_MINUTES = 30;

function getExpiration(timestamp) {
  if (typeof timestamp !== 'string' || timestamp.trim() === '') return '';

  const time = Date.parse(timestamp);
  if (!Number.isFinite(time)) return '';

  const expirationTime = time + EXPIRATION_MINUTES * 60 * 1000;
  if (!Number.isFinite(expirationTime)) return '';

  const expiration = new Date(expirationTime);
  return Number.isFinite(expiration.getTime()) ? expiration.toISOString() : '';
}

function safeLogValue(value, fallback = '-') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value).replace(/[\u0000-\u001f\u007f]/g, ' ');
}

export async function respond({ root, decisions, alerts }) {
  const decisionList = Array.isArray(decisions) ? decisions : [];
  const alertList = Array.isArray(alerts) ? alerts : [];
  const rules = [];
  const logLines = [];
  let skippedInvalidTimestamp = 0;

  for (const decision of decisionList) {
    const alertId = typeof decision?.alertId === 'string' ? decision.alertId : '';
    const alert = alertList.find((item) => item?.id === alertId);
    const timestamp = safeLogValue(alert?.timestamp);
    const sourceAddress = alert?.data?.srcip;
    const hasValidSource = typeof sourceAddress === 'string' && sourceAddress.trim() !== '';
    const source = hasValidSource ? safeLogValue(sourceAddress) : '-';
    const action = safeLogValue(decision?.action, 'unknown');

    if (!alert) {
      logLines.push(`timestamp=- alert=${safeLogValue(alertId)} action=${action} source=- expiresAt=-`);
      continue;
    }

    if (decision?.action !== 'block') {
      logLines.push(`timestamp=${timestamp} alert=${safeLogValue(alert.id)} action=${action} source=${source} expiresAt=-`);
      continue;
    }

    if (!hasValidSource) {
      logLines.push(`timestamp=${timestamp} alert=${safeLogValue(alert.id)} action=block_skipped_invalid_source source=- expiresAt=- reason=missing_or_invalid_source`);
      continue;
    }

    const expiration = getExpiration(alert.timestamp);
    if (!expiration) {
      skippedInvalidTimestamp += 1;
      logLines.push(`timestamp=${timestamp} alert=${safeLogValue(alert.id)} action=block_skipped_invalid_timestamp source=${source} expiresAt=-`);
      continue;
    }

    const rule = {
      action: 'deny',
      source: sourceAddress,
      expiresAt: expiration,
      sourceAlert: alert.id,
    };
    rules.push(rule);
    logLines.push(`timestamp=${timestamp} alert=${safeLogValue(alert.id)} action=deny source=${source} expiresAt=${expiration}`);
  }

  if (logLines.length > 0) {
    await appendFile(join(root, 'xdr', 'alerts.log'), `${logLines.join('\n')}\n`, 'utf8');
  }

  // scripts/xdr-run.mjs는 web-injection 응답기를 호출하며, 응답기는 차단 후보 규칙을 반환하고 xdr/alerts.log에 경보별 기록을 추가합니다.
  // 반환된 차단 후보 규칙은 실제 ZTNA 판정기에 적용되지 않습니다.
  return {
    rules,
    blocked: rules.length,
    normalBlocked: false,
    skippedInvalidTimestamp,
  };
}
