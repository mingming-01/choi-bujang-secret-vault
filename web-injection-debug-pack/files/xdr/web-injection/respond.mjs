import { appendFile, readFile } from 'node:fs/promises';
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
  const compressed = compressionIndex !== -1;
  const leftText = compressed ? input.slice(0, compressionIndex) : input;
  const rightText = compressed ? input.slice(compressionIndex + 2) : '';
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...right];
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return null;
  if (compressed) {
    if (groups.length >= 8) return null;
    const zeros = Array(8 - groups.length).fill('0');
    return [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16));
  }
  if (groups.length !== 8) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

function normalizeIp(value) {
  if (typeof value !== 'string') return '';
  const input = value.trim();
  if (!input || /[\s/]/.test(input)) return '';
  const ipv4 = parseIpv4(input);
  if (ipv4) return ipv4.join('.');
  const ipv6 = parseIpv6(input);
  return ipv6 ? ipv6.map((group) => group.toString(16).padStart(4, '0')).join(':') : '';
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

  for (const decision of decisionList) {
    const alertId = typeof decision?.alertId === 'string' ? decision.alertId : '';
    const alert = alertList.find((item) => item?.id === alertId);
    const timestamp = safeLogValue(alert?.timestamp);
    const normalizedSource = alert ? getValidSource(alert) : '';
    const hasValidSource = normalizedSource !== '';
    const source = hasValidSource ? normalizedSource : '-';
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

    rules.push({ action: 'deny', source: normalizedSource, expiresAt: expiration, sourceAlert: alert.id });
    logLines.push(`timestamp=${timestamp} alert=${safeLogValue(alert.id)} action=deny source=${source} expiresAt=${expiration}`);
  }

  if (logLines.length > 0) {
    const logPath = join(root, 'xdr', 'alerts.log');
    let existingLog = '';
    try {
      existingLog = await readFile(logPath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const existingLines = new Set(existingLog.split(/\r?\n/));
    const newLines = logLines.filter((line) => {
      if (existingLines.has(line)) return false;
      existingLines.add(line);
      return true;
    });
    if (newLines.length > 0) {
      const separator = existingLog !== '' && !/(?:\r?\n)$/.test(existingLog) ? '\n' : '';
      await appendFile(logPath, `${separator}${newLines.join('\n')}\n`, 'utf8');
    }
  }

  // The deny rules are candidates only; they are not applied to the existing ZTNA policy.
  return { rules, blocked: rules.length, normalBlocked: false, skippedInvalidTimestamp };
}
