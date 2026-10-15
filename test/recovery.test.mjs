import test from 'node:test';
import assert from 'node:assert/strict';

import {
  loadVerifiedPolicyFixture,
  loadVerifiedCurrentPolicyFixture,
  compareFixturePolicies,
  fixtureReadAllowed,
  restoreFixturePolicies,
} from '../src/recovery.mjs';

test('정책 복구는 대상 정책만 복구하고 접근 판정과 감사 기록을 보존한다', async () => {
  const safeSnapshot = await loadVerifiedPolicyFixture();
  const currentSnapshot = await loadVerifiedCurrentPolicyFixture();

  const policyIds = [
    'note.read.owner',
    'note.read.cross-user',
  ];

  const comparison = compareFixturePolicies({
    safeSnapshot,
    currentSnapshot,
    policyIds,
  });

  assert.ok(
    comparison.changes.some(
      change => change.id === 'note.read.cross-user',
    ),
    '교차 사용자 정책 변경을 찾아야 한다',
  );

  // 복구 전: 잘못된 교차 사용자 허용 정책을 확인한다.
  assert.equal(
    fixtureReadAllowed({
      policySnapshot: currentSnapshot,
      requesterId: 'another-user',
      ownerId: 'fixture-owner-b',
    }),
    true,
  );

  // 잘못된 확인 문자열로는 복구할 수 없어야 한다.
  assert.throws(
    () => restoreFixturePolicies({
      safeSnapshot,
      currentSnapshot,
      policyIds,
      confirmation: 'wrong-confirmation',
    }),
    /policy_restore_confirmation_required/,
  );

  const restored = restoreFixturePolicies({
    safeSnapshot,
    currentSnapshot,
    policyIds,
    confirmation: comparison.confirmation,
  });

  // 복구 후: 소유자는 접근할 수 있어야 한다.
  assert.equal(
    fixtureReadAllowed({
      policySnapshot: restored,
      requesterId: 'fixture-owner-b',
      ownerId: 'fixture-owner-b',
    }),
    true,
  );

  // 복구 후: 다른 사용자의 접근은 거부되어야 한다.
  assert.equal(
    fixtureReadAllowed({
      policySnapshot: restored,
      requesterId: 'another-user',
      ownerId: 'fixture-owner-b',
    }),
    false,
  );

  // 복구 범위 밖의 정책은 유지되어야 한다.
  assert.deepEqual(
    restored.policies.find(policy => policy.id === 'notice.read.public'),
    currentSnapshot.policies.find(policy => policy.id === 'notice.read.public'),
  );

  // 기존 감사 기록은 유지되어야 한다.
  assert.deepEqual(
    restored.auditEvents,
    currentSnapshot.auditEvents,
  );

  assert.equal(restored.revision, safeSnapshot.revision);
});

import {
  loadVerifiedMemoFixture,
  loadVerifiedMemoCurrentFixture,
  restoreFixtureMemo,
} from '../src/recovery.mjs';

test('메모 복구는 지정된 메모만 복구하고 다른 메모와 감사 기록을 보존한다', async () => {
  const backup = await loadVerifiedMemoFixture();
  const currentStore = await loadVerifiedMemoCurrentFixture();

  const target = {
    id: backup.id,
    ownerId: backup.ownerId,
    contentSha256: backup.contentSha256,
  };

  const confirmation =
    `RESTORE ${backup.id} ${backup.ownerId} ${backup.contentSha256}`;

  // 확인 문자열이 틀리면 복구를 거부해야 한다.
  assert.throws(
    () => restoreFixtureMemo({
      backup,
      currentStore,
      target,
      confirmation: 'wrong-confirmation',
    }),
    /memo_restore_confirmation_required/,
  );

  const restoredStore = restoreFixtureMemo({
    backup,
    currentStore,
    target,
    confirmation,
  });

  const restoredMemo = restoredStore.memos.find(
    memo => memo.id === backup.id,
  );

  assert.ok(restoredMemo, '복구 대상 메모가 있어야 한다');
  assert.equal(restoredMemo.ownerId, backup.ownerId);
  assert.equal(restoredMemo.title, backup.title);
  assert.equal(restoredMemo.body, backup.body);

  // 대상 메모 이외의 데이터는 변경되면 안 된다.
  assert.deepEqual(
    restoredStore.memos.filter(memo => memo.id !== backup.id),
    currentStore.memos.filter(memo => memo.id !== backup.id),
  );

  assert.deepEqual(
    restoredStore.auditEvents,
    currentStore.auditEvents,
  );
});