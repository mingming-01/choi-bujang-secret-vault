import { randomUUID } from 'node:crypto';
import { RULE_IDS } from '../src/decider.mjs';
import { getRuntime, loadVerifiedBackup } from './restore.js';

const BEARER_TOKEN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;
const RESTORE_ERRORS = Object.freeze({
  backup_not_configured: 'RESTORE_BACKUP_NOT_CONFIGURED',
  backup_unavailable: 'RESTORE_BACKUP_UNAVAILABLE',
  backup_integrity_failed: 'RESTORE_BACKUP_UNVERIFIED',
  backup_invalid: 'RESTORE_BACKUP_INVALID',
  backup_too_large: 'RESTORE_BACKUP_INVALID',
});

export function createWarRoomHandler({
  runtimeProvider = getRuntime,
  backupLoader = loadVerifiedBackup,
  ruleIds = RULE_IDS,
} = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store, max-age=0');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }

    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string' || !BEARER_TOKEN.test(authorization)) {
      return response.status(401).json({ error: 'AUTHENTICATION_REQUIRED' });
    }

    let runtime;
    let identity;
    try {
      runtime = runtimeProvider();
      identity = await runtime.verifyLogin(authorization);
    } catch {
      return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
    }
    if (!identity || identity.kind !== 'student' || typeof identity.userId !== 'string') {
      return response.status(403).json({ error: 'WAR_ROOM_NOT_ALLOWED' });
    }

    let deviceApproval = { status: 'unavailable' };
    try {
      const { data, error } = await runtime.supabase.from('device_credentials')
        .select('status')
        .eq('user_id', identity.userId);
      if (error || !Array.isArray(data)) throw new Error('device_status_unavailable');
      const counts = { approved: 0, pending: 0, rejected: 0, other: 0 };
      for (const row of data) {
        if (row && Object.hasOwn(counts, row.status)) counts[row.status] += 1;
        else counts.other += 1;
      }
      deviceApproval = { status: 'available', counts };
    } catch {
      // A missing or unavailable table is shown as unavailable, never as zero devices.
    }

    let recovery = { status: 'unavailable', reason: 'RESTORE_UNAVAILABLE' };
    try {
      const { backup, backupSha256 } = await backupLoader(runtime);
      if (!backup || backup.ownerId !== identity.userId) {
        recovery = { status: 'not_available_for_user' };
      } else if (typeof backup.revision === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(backup.revision)
          && typeof backupSha256 === 'string' && /^[a-f0-9]{64}$/u.test(backupSha256)) {
        recovery = { status: 'verified', revision: backup.revision };
      }
    } catch (error) {
      const code = typeof error?.message === 'string' ? error.message : '';
      recovery = { status: 'unavailable', reason: RESTORE_ERRORS[code] || 'RESTORE_UNAVAILABLE' };
    }

    return response.status(200).json({
      schema: 'aleph.war-room.summary.v1',
      requestId: randomUUID(),
      checkedAt: new Date().toISOString(),
      decision: { status: 'available', ruleIds: [...ruleIds] },
      detection: {
        status: 'not_connected',
        eventCount: null,
        message: 'src/detect.mjs는 로컬 탐지 규칙이며 운영 사건을 수집·저장하는 API는 연결되어 있지 않습니다.',
      },
      revocation: {
        status: 'not_executed',
        message: '탐지의 회수 제안과 실제 세션·기기 회수 실행은 다릅니다. 현재 실제 회수 실행 API는 연결되어 있지 않습니다.',
      },
      deviceApproval,
      recovery,
      serverRecords: {
        status: 'not_connected',
        count: null,
        message: '앱에서 조회할 수 있는 저장형 운영 로그 API가 없습니다. 기록 수를 0건으로 추정하지 않습니다.',
      },
    });
  };
}

export default createWarRoomHandler();
