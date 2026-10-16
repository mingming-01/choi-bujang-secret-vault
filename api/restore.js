import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyDeviceRequest } from '../src/device-approval.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NOTE_ID = /^[1-9][0-9]{0,17}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_BACKUP_BYTES = 128 * 1024;
let runtime;

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function getRuntime() {
  if (runtime) return runtime;
  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) throw new Error('service_not_configured');

  const serviceUrl = new URL(supabaseUrl);
  const issuer = new URL(config.identityProvider.issuer);
  if (serviceUrl.protocol !== 'https:' || serviceUrl.origin !== issuer.origin
      || !['', '/'].includes(serviceUrl.pathname) || serviceUrl.username || serviceUrl.password) {
    throw new Error('service_not_configured');
  }
  const supabase = createClient(serviceUrl.origin, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  runtime = {
    supabase,
    verifyLogin: createLoginVerifier({ config, supabaseSecretKey: secretKey, supabaseClient: supabase }),
    serviceOrigin: serviceUrl.origin,
    secretKey,
  };
  return runtime;
}

function parseBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    if (body.length > 4096) return null;
    try { body = JSON.parse(body); } catch { return null; }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const keys = Object.keys(body).sort();
  if (keys.some(key => !['id', 'ownerId', 'contentSha256', 'confirmation'].includes(key))
      || !['contentSha256', 'id', 'ownerId'].every(key => Object.hasOwn(body, key))
      || typeof body.id !== 'string' || !NOTE_ID.test(body.id)
      || typeof body.ownerId !== 'string' || !UUID.test(body.ownerId)
      || typeof body.contentSha256 !== 'string' || !SHA256.test(body.contentSha256)
      || (Object.hasOwn(body, 'confirmation')
        && (typeof body.confirmation !== 'string' || body.confirmation.length > 512))) return null;
  return body;
}

async function readLimited(response) {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_BACKUP_BYTES) {
    throw new Error('backup_too_large');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('backup_unavailable');
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BACKUP_BYTES) {
        await reader.cancel();
        throw new Error('backup_too_large');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, length);
}

function validateBackup(backup) {
  if (!backup || typeof backup !== 'object' || Array.isArray(backup)
      || Object.keys(backup).sort().join(',') !== 'content,contentSha256,environment,id,ownerId,revision,schema,title'
      || backup.schema !== 'aleph.note-backup.v1' || backup.environment !== 'production-backup'
      || typeof backup.revision !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(backup.revision)
      || typeof backup.id !== 'string' || !NOTE_ID.test(backup.id)
      || typeof backup.ownerId !== 'string' || !UUID.test(backup.ownerId)
      || typeof backup.title !== 'string' || !backup.title.trim() || backup.title.length > 200
      || typeof backup.content !== 'string' || backup.content.length > 20000
      || typeof backup.contentSha256 !== 'string' || !SHA256.test(backup.contentSha256)
      || sha256(backup.content) !== backup.contentSha256) {
    throw new Error('backup_invalid');
  }
  return backup;
}

async function loadVerifiedBackup(currentRuntime) {
  const backupUrlValue = process.env.RESTORE_BACKUP_URL;
  const expectedSha256 = process.env.RESTORE_BACKUP_SHA256;
  if (typeof backupUrlValue !== 'string' || !backupUrlValue || !SHA256.test(expectedSha256 ?? '')) {
    throw new Error('backup_not_configured');
  }
  let backupUrl;
  try { backupUrl = new URL(backupUrlValue); } catch { throw new Error('backup_not_configured'); }
  if (backupUrl.protocol !== 'https:' || backupUrl.origin !== currentRuntime.serviceOrigin
      || !/^\/storage\/v1\/object\/(?!public(?:\/|$))[^/]+\/.+$/u.test(backupUrl.pathname)
      || backupUrl.username || backupUrl.password || backupUrl.search || backupUrl.hash) {
    throw new Error('backup_not_configured');
  }

  let response;
  try {
    response = await fetch(backupUrl, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: {
        apikey: currentRuntime.secretKey,
        authorization: `Bearer ${currentRuntime.secretKey}`,
        accept: 'application/json',
      },
    });
  } catch {
    throw new Error('backup_unavailable');
  }
  if (!response.ok) throw new Error('backup_unavailable');
  const bytes = await readLimited(response);
  const backupSha256 = createHash('sha256').update(bytes).digest('hex');
  if (backupSha256 !== expectedSha256) throw new Error('backup_integrity_failed');
  let parsed;
  try { parsed = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('backup_invalid'); }
  return { backup: validateBackup(parsed), backupSha256 };
}

async function readCurrentMemo(client, backup) {
  const { data, error } = await client.from('learning_notes')
    .select('id, owner_id, title, content')
    .eq('id', backup.id)
    .maybeSingle();
  if (error) throw new Error('notes_unavailable');
  if (!data) return null;
  if (String(data.id) !== backup.id || data.owner_id !== backup.ownerId
      || typeof data.title !== 'string' || typeof data.content !== 'string') {
    throw new Error('restore_target_mismatch');
  }
  return { id: String(data.id), ownerId: data.owner_id, title: data.title, content: data.content };
}

function planFor(backup, current, backupSha256) {
  const currentStateSha256 = current ? sha256(canonical(current)) : 'missing';
  const changedFields = current
    ? ['title', 'content'].filter(key => current[key] !== (key === 'content' ? backup.content : backup.title))
    : ['insert memo'];
  // Bind confirmation to every byte of the verified snapshot and to the pre-write row state.
  const confirmation = `RESTORE ${backup.revision} ${backupSha256} ${backup.id} ${backup.ownerId} ${backup.contentSha256} ${currentStateSha256}`;
  return { changedFields, confirmation };
}

function responseJson(response, status, value) {
  return response.status(status).json(value);
}

function errorResponse(response, error) {
  const code = error?.message;
  if (code === 'backup_not_configured') return responseJson(response, 503, { error: 'RESTORE_BACKUP_NOT_CONFIGURED' });
  if (code === 'backup_unavailable') return responseJson(response, 503, { error: 'RESTORE_BACKUP_UNAVAILABLE' });
  if (code === 'backup_integrity_failed') return responseJson(response, 503, { error: 'RESTORE_BACKUP_UNVERIFIED' });
  if (code === 'backup_invalid' || code === 'backup_too_large') return responseJson(response, 503, { error: 'RESTORE_BACKUP_INVALID' });
  if (code === 'restore_target_mismatch') return responseJson(response, 409, { error: 'RESTORE_TARGET_MISMATCH' });
  if (code === 'notes_unavailable') return responseJson(response, 502, { error: 'NOTES_UNAVAILABLE' });
  return responseJson(response, 503, { error: 'RESTORE_UNAVAILABLE' });
}

// POST /api/restore. A request without confirmation is a read-only preview.
export function createRestoreHandler(
  {
    runtimeProvider = getRuntime,
    backupLoader = loadVerifiedBackup,
  } = {},
) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store, max-age=0');
    response.setHeader('X-Content-Type-Options', 'nosniff');

    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return responseJson(response, 405, {
        error: 'METHOD_NOT_ALLOWED',
      });
    }

    const input = parseBody(request);

    if (!input) {
      return responseJson(response, 400, {
        error: 'INVALID_RESTORE_REQUEST',
      });
    }

    const authorization = request.headers?.authorization;

    if (
      typeof authorization !== 'string'
      || !authorization.startsWith('Bearer ')
    ) {
      return responseJson(response, 401, {
        error: 'AUTHENTICATION_REQUIRED',
      });
    }

    let currentRuntime;
    let identity;

    try {
      currentRuntime = runtimeProvider();
      identity = await currentRuntime.verifyLogin(authorization);
    } catch {
      return responseJson(response, 401, {
        error: 'INVALID_AUTHENTICATION',
      });
    }

    if (
      !identity
      || !['student', 'judge'].includes(identity.kind)
      || (identity.kind === 'judge' && identity.identity !== 'b')
    ) {
      return responseJson(response, 403, {
        error: 'RESTORE_NOT_ALLOWED',
      });
    }

    // 학생의 복구 요청은 승인된 기기의 서명을 확인합니다.
    // 심판용 가상 복구 요청의 기존 흐름은 유지합니다.
    if (identity.kind === 'student') {
      let deviceCheck;

      try {
        deviceCheck = await verifyDeviceRequest(request, {
          supabase: currentRuntime.supabase,
          userId: identity.userId,
          config,
        });
      } catch {
        return responseJson(response, 503, {
          error: 'DEVICE_APPROVAL_UNAVAILABLE',
        });
      }

      if (!deviceCheck.ok) {
        return responseJson(response, deviceCheck.status, {
          error: deviceCheck.error,
        });
      }
    }

    let backup;
    let backupSha256;

    try {
      // 백업은 미리보기 요청과 실제 복원 요청 모두에서 다시 검증한다.
      ({ backup, backupSha256 } = await backupLoader(currentRuntime));
    } catch (error) {
      return errorResponse(response, error);
    }

    if (
      input.id !== backup.id
      || input.ownerId !== backup.ownerId
      || input.contentSha256 !== backup.contentSha256
      || (
        identity.kind === 'student'
        && identity.userId !== backup.ownerId
      )
    ) {
      return responseJson(response, 403, {
        error: 'RESTORE_NOT_ALLOWED',
      });
    }

    let current;

    try {
      current = await readCurrentMemo(
        currentRuntime.supabase,
        backup,
      );
    } catch (error) {
      return errorResponse(response, error);
    }

    const plan = planFor(backup, current, backupSha256);

    const preview = {
      revision: backup.revision,
      backupSha256,
      target: {
        id: backup.id,
        ownerId: backup.ownerId,
        contentSha256: backup.contentSha256,
      },
      changedFields: plan.changedFields,
      confirmation: plan.confirmation,
    };

    // 첫 요청은 복원 계획만 반환하고 데이터를 변경하지 않는다.
    if (input.confirmation === undefined) {
      return responseJson(response, 200, { preview });
    }

    // 현재 데이터 상태에 맞는 확인값인지 검사한다.
    if (input.confirmation !== plan.confirmation) {
      return responseJson(response, 409, {
        error: 'RESTORE_CONFIRMATION_REQUIRED',
        preview,
      });
    }

    if (plan.changedFields.length === 0) {
      return responseJson(response, 200, {
        restored: false,
        reason: 'ALREADY_MATCHES_BACKUP',
        ...preview,
      });
    }

    try {
      let writeResult;

      if (current === null) {
        // 백업 대상 메모가 없으면 해당 메모 한 건만 추가한다.
        writeResult = await currentRuntime.supabase
          .from('learning_notes')
          .insert({
            id: backup.id,
            owner_id: backup.ownerId,
            title: backup.title,
            content: backup.content,
          })
          .select('id')
          .maybeSingle();
      } else {
        // 기존 메모는 확인 당시의 값이 그대로일 때만 수정한다.
        writeResult = await currentRuntime.supabase
          .from('learning_notes')
          .update({
            title: backup.title,
            content: backup.content,
          })
          .eq('id', backup.id)
          .eq('owner_id', backup.ownerId)
          .eq('title', current.title)
          .eq('content', current.content)
          .select('id')
          .maybeSingle();
      }

      if (writeResult.error || !writeResult.data) {
        return responseJson(response, 409, {
          error: 'RESTORE_CONCURRENT_CHANGE',
        });
      }

      // 실제 저장된 결과를 다시 읽어 백업과 대조한다.
      const restored = await readCurrentMemo(
        currentRuntime.supabase,
        backup,
      );

      if (
        !restored
        || restored.id !== backup.id
        || restored.ownerId !== backup.ownerId
        || restored.title !== backup.title
        || sha256(restored.content) !== backup.contentSha256
      ) {
        return responseJson(response, 409, {
          error: 'RESTORE_POSTCHECK_FAILED',
        });
      }

      // 다른 메모, 감사 로그, 정책 설정은 이 핸들러에서 수정하지 않는다.
      return responseJson(response, 200, {
        restored: true,
        revision: backup.revision,
        target: {
          id: restored.id,
          ownerId: restored.ownerId,
          contentSha256: sha256(restored.content),
        },
        changedFields: plan.changedFields,
      });
    } catch {
      return responseJson(response, 502, {
        error: 'RESTORE_WRITE_FAILED',
      });
    }
  };
}

export default createRestoreHandler();
