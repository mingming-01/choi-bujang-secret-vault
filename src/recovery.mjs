import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Pinned digests authenticate repository-owned TRAINING FIXTURES only.
// They are not evidence of a pre-incident or production backup.
const POLICY_FIXTURE_SHA256 = 'f3a70d605e58a0cbe03ec1a6c16f29717ca2bfa2a017e4bf5769d88b47890a9a';
const POLICY_CURRENT_FIXTURE_SHA256 = '0571e44a14cd92fb1e9fb6042bf302e271ab18600ee3abb3452e4ee7e18a3155';
const MEMO_FIXTURE_SHA256 = '11676807ed766a435a22b74f54057546e6313a287a4d447c42d33ed8e29ee3e6';
const MEMO_CURRENT_FIXTURE_SHA256 = 'c4bf70e50fa30d44ee7e1b593accc0d56864cb4ba6fd43845aea8ac65f24c687';
const MEMO_CONTENT_FIXTURE_SHA256 = '64db0d5cf9d3eca69529df51bb023a52f9f7a7c124e54adf63c318f1fd1c43c5';
const VERIFIED_POLICY_FIXTURES = new WeakMap();
const VERIFIED_POLICY_CURRENT_FIXTURES = new WeakMap();
const VERIFIED_MEMO_FIXTURES = new WeakMap();
const VERIFIED_MEMO_CURRENT_FIXTURES = new WeakMap();
const HEX_SHA256 = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!object(value)) return JSON.stringify(value);
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function validatePolicies(value) {
  if (!Array.isArray(value)) throw new TypeError('invalid_fixture_policies');
  const ids = new Set();
  for (const policy of value) {
    if (!object(policy) || Object.keys(policy).sort().join(',') !== 'condition,effect,id'
        || typeof policy.id !== 'string' || !/^[a-z][a-z0-9_.-]{0,79}$/u.test(policy.id)
        || !['allow', 'deny'].includes(policy.effect) || typeof policy.condition !== 'string'
        || ids.has(policy.id)) {
      throw new TypeError('invalid_fixture_policy');
    }
    ids.add(policy.id);
  }
}

function validatePolicySnapshot(snapshot) {
  if (!object(snapshot) || snapshot.schema !== 'aleph.training-policy.v1'
      || snapshot.environment !== 'fixture-only'
      || typeof snapshot.revision !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(snapshot.revision)
      || Object.keys(snapshot).some(key => !['schema', 'environment', 'revision', 'policies', 'auditEvents'].includes(key))
      || (Object.hasOwn(snapshot, 'auditEvents') && !Array.isArray(snapshot.auditEvents))) {
    throw new TypeError('invalid_fixture_policy_snapshot');
  }
  validatePolicies(snapshot.policies);
}

function validateMemoStore(store) {
  if (!object(store) || store.schema !== 'aleph.training-memo-store.v1'
      || store.environment !== 'fixture-only' || !Array.isArray(store.memos)
      || !Array.isArray(store.auditEvents)) {
    throw new TypeError('invalid_fixture_memo_store');
  }
  const ids = new Set();
  for (const memo of store.memos) {
    if (!object(memo) || !UUID.test(memo.id ?? '')
        || typeof memo.ownerId !== 'string' || !memo.ownerId.trim()
        || typeof memo.title !== 'string' || typeof memo.body !== 'string'
        || ids.has(memo.id)) {
      throw new TypeError('invalid_fixture_memo');
    }
    ids.add(memo.id);
  }
}

function requireVerifiedSnapshot(snapshot, verifiedSet, failureCode, validate) {
  const fingerprint = object(snapshot) ? verifiedSet.get(snapshot) : undefined;
  if (!fingerprint || sha256(canonical(snapshot)) !== fingerprint) throw new Error(failureCode);
  validate(snapshot);
}

export async function loadVerifiedPolicyFixture(path = new URL('../test/fixtures/recovery/policy-safe.json', import.meta.url)) {
  const bytes = await readFile(path);
  if (sha256Bytes(bytes) !== POLICY_FIXTURE_SHA256) {
    throw new Error('policy_fixture_integrity_failed');
  }
  const snapshot = JSON.parse(bytes.toString('utf8'));
  validatePolicySnapshot(snapshot);
  const verified = structuredClone(snapshot);
  VERIFIED_POLICY_FIXTURES.set(verified, sha256(canonical(verified)));
  return verified;
}

export async function loadVerifiedCurrentPolicyFixture(
  path = new URL('../test/fixtures/recovery/policy-current.json', import.meta.url),
) {
  const bytes = await readFile(path);
  if (sha256Bytes(bytes) !== POLICY_CURRENT_FIXTURE_SHA256) {
    throw new Error('policy_current_fixture_integrity_failed');
  }
  const snapshot = JSON.parse(bytes.toString('utf8'));
  validatePolicySnapshot(snapshot);
  const verified = structuredClone(snapshot);
  VERIFIED_POLICY_CURRENT_FIXTURES.set(verified, sha256(canonical(verified)));
  return verified;
}

function requireVerifiedPolicyFixture(snapshot) {
  requireVerifiedSnapshot(snapshot, VERIFIED_POLICY_FIXTURES, 'unverified_policy_fixture', validatePolicySnapshot);
}

function validateScope(policyIds) {
  if (!Array.isArray(policyIds) || policyIds.length === 0
      || policyIds.length > 80 || policyIds.some(id => typeof id !== 'string')
      || new Set(policyIds).size !== policyIds.length) {
    throw new TypeError('invalid_policy_scope');
  }
  return [...policyIds].sort();
}

export function compareFixturePolicies({ safeSnapshot, currentSnapshot, policyIds }) {
  requireVerifiedPolicyFixture(safeSnapshot);
  requireVerifiedSnapshot(
    currentSnapshot, VERIFIED_POLICY_CURRENT_FIXTURES, 'unverified_current_policy_fixture', validatePolicySnapshot,
  );
  const scope = validateScope(policyIds);
  const safeById = new Map(safeSnapshot.policies.map(item => [item.id, item]));
  const currentById = new Map(currentSnapshot.policies.map(item => [item.id, item]));
  if (scope.some(id => !safeById.has(id) && !currentById.has(id))) {
    throw new Error('unknown_policy_scope_target');
  }
  const changes = [];

  for (const id of scope) {
    const safePolicy = safeById.get(id) ?? null;
    const currentPolicy = currentById.get(id) ?? null;
    if (canonical(safePolicy) !== canonical(currentPolicy)) {
      changes.push({ id, safe: safePolicy, current: currentPolicy });
    }
  }

  const diffSha256 = sha256(canonical(changes));
  return Object.freeze({
    safeRevision: safeSnapshot.revision,
    currentRevision: currentSnapshot.revision,
    policyIds: Object.freeze(scope),
    changes: Object.freeze(changes),
    diffSha256,
    confirmation: `RESTORE ${safeSnapshot.revision} ${scope.join(',')} ${diffSha256}`,
  });
}

// Exercise only these fixture policies; this is not a production policy engine.
export function fixtureReadAllowed({ policySnapshot, requesterId, ownerId }) {
  validatePolicySnapshot(policySnapshot);
  if (typeof requesterId !== 'string' || !requesterId
      || typeof ownerId !== 'string' || !ownerId) return false;
  const byId = new Map(policySnapshot.policies.map(policy => [policy.id, policy]));
  if (requesterId === ownerId) {
    const policy = byId.get('note.read.owner');
    return policy?.effect === 'allow' && policy.condition === 'owner_id_matches';
  }
  const policy = byId.get('note.read.cross-user');
  return policy?.effect === 'allow'
    && policy.condition === 'any_authenticated_user';
}

export function restoreFixturePolicies({ safeSnapshot, currentSnapshot, policyIds, confirmation }) {
  // Preview names the target revision, exact policy IDs, content diff, and required confirmation.
  // No restored output is produced until its complete confirmation is supplied.
  const comparison = compareFixturePolicies({ safeSnapshot, currentSnapshot, policyIds });
  if (confirmation !== comparison.confirmation) throw new Error('policy_restore_confirmation_required');

  const safeById = new Map(safeSnapshot.policies.map(item => [item.id, item]));
  const scope = new Set(comparison.policyIds);
  const restoredPolicies = currentSnapshot.policies
    .filter(policy => !scope.has(policy.id))
    .map(policy => structuredClone(policy));

  for (const id of comparison.policyIds) {
    const safePolicy = safeById.get(id);
    if (safePolicy) restoredPolicies.push(structuredClone(safePolicy));
  }

  validatePolicies(restoredPolicies);
  return {
    ...structuredClone(currentSnapshot),
    revision: safeSnapshot.revision,
    policies: restoredPolicies,
  };
}

export async function loadVerifiedMemoFixture(
  path = new URL('../test/fixtures/recovery/memo-backup.json', import.meta.url),
  contentPath = new URL('../test/fixtures/recovery/memo-content.txt', import.meta.url),
) {
  const [bytes, contentBytes] = await Promise.all([readFile(path), readFile(contentPath)]);
  if (sha256Bytes(bytes) !== MEMO_FIXTURE_SHA256) throw new Error('memo_fixture_integrity_failed');
  if (sha256Bytes(contentBytes) !== MEMO_CONTENT_FIXTURE_SHA256) {
    throw new Error('memo_content_fixture_integrity_failed');
  }
  const backup = JSON.parse(bytes.toString('utf8'));
  const content = contentBytes.toString('utf8');
  if (!object(backup) || backup.schema !== 'aleph.training-memo-backup.v1'
      || backup.environment !== 'fixture-only' || !UUID.test(backup.id ?? '')
      || typeof backup.ownerId !== 'string' || !backup.ownerId.trim()
      || typeof backup.title !== 'string' || !backup.title.trim()
      || typeof backup.body !== 'string' || !HEX_SHA256.test(backup.contentSha256 ?? '')
      || sha256(backup.body) !== backup.contentSha256 || backup.body !== content) {
    throw new Error('memo_fixture_content_integrity_failed');
  }
  const verified = structuredClone(backup);
  VERIFIED_MEMO_FIXTURES.set(verified, sha256(canonical(verified)));
  return verified;
}

export async function loadVerifiedMemoCurrentFixture(
  path = new URL('../test/fixtures/recovery/memo-current.json', import.meta.url),
) {
  const bytes = await readFile(path);
  if (sha256Bytes(bytes) !== MEMO_CURRENT_FIXTURE_SHA256) {
    throw new Error('memo_current_fixture_integrity_failed');
  }
  const store = JSON.parse(bytes.toString('utf8'));
  validateMemoStore(store);
  const verified = structuredClone(store);
  VERIFIED_MEMO_CURRENT_FIXTURES.set(verified, sha256(canonical(verified)));
  return verified;
}

function requireVerifiedMemoFixture(backup) {
  requireVerifiedSnapshot(backup, VERIFIED_MEMO_FIXTURES, 'unverified_memo_fixture', value => {
    if (sha256(value.body) !== value.contentSha256) throw new Error('memo_fixture_content_integrity_failed');
  });
}

export function restoreFixtureMemo({ backup, currentStore, target, confirmation }) {
  requireVerifiedMemoFixture(backup);
  requireVerifiedSnapshot(currentStore, VERIFIED_MEMO_CURRENT_FIXTURES,
    'unverified_current_memo_fixture', validateMemoStore);
  if (!object(target)) throw new TypeError('invalid_memo_restore_target');

  if (target.id !== backup.id || target.ownerId !== backup.ownerId
      || target.contentSha256 !== backup.contentSha256) {
    throw new Error('memo_backup_target_mismatch');
  }
  const matches = currentStore.memos.filter(memo => memo.id === target.id);
  if (matches.length !== 1 || matches[0].ownerId !== target.ownerId) {
    throw new Error('memo_current_target_mismatch');
  }
  const expectedConfirmation = `RESTORE ${backup.id} ${backup.ownerId} ${backup.contentSha256}`;
  if (confirmation !== expectedConfirmation) throw new Error('memo_restore_confirmation_required');

  const untouchedMemos = currentStore.memos.filter(memo => memo.id !== backup.id);
  const restoredMemo = {
    id: backup.id,
    ownerId: backup.ownerId,
    title: backup.title,
    body: backup.body,
  };
  const restoredStore = {
    ...structuredClone(currentStore),
    memos: currentStore.memos.map(memo => memo.id === backup.id ? restoredMemo : structuredClone(memo)),
  };
  const restored = restoredStore.memos.find(memo => memo.id === backup.id);
  if (restored.id !== backup.id || restored.ownerId !== backup.ownerId
      || sha256(restored.body) !== backup.contentSha256) {
    throw new Error('memo_restore_postcheck_failed');
  }
  const restoredUntouched = restoredStore.memos.filter(memo => memo.id !== backup.id);
  if (canonical(restoredUntouched) !== canonical(untouchedMemos)
      || canonical(restoredStore.auditEvents) !== canonical(currentStore.auditEvents)) {
    throw new Error('memo_restore_preservation_check_failed');
  }
  return restoredStore;
}

// These paths identify local fixture files only, never production backups.
export const trainingFixturePaths = Object.freeze({
  policy: fileURLToPath(new URL('../test/fixtures/recovery/policy-safe.json', import.meta.url)),
  policyCurrent: fileURLToPath(new URL('../test/fixtures/recovery/policy-current.json', import.meta.url)),
  memo: fileURLToPath(new URL('../test/fixtures/recovery/memo-backup.json', import.meta.url)),
  memoCurrent: fileURLToPath(new URL('../test/fixtures/recovery/memo-current.json', import.meta.url)),
  memoContent: fileURLToPath(new URL('../test/fixtures/recovery/memo-content.txt', import.meta.url)),
});
