import assert from 'node:assert/strict';
import { isDeniedByTemporaryRules } from '../src/temporary-deny.mjs';

const now = Date.parse('2026-10-17T12:00:00.000Z');
const patterns = {
  decodePasses: 2,
  patterns: [
    { id: 'sql-injection', source: '\\bunion\\s+(?:all\\s+)?select\\b', flags: 'i' },
  ],
};
const activeDeny = {
  action: 'deny',
  source: '192.0.2.10',
  expiresAt: '2026-10-17T12:30:00.000Z',
  sourceAlert: 'virtual-alert-1',
  patternId: 'sql-injection',
};
const attackRequest = {
  ip: '192.0.2.10',
  url: '/api/notes?q=UNION%20SELECT%20name',
};

const cases = [
  {
    name: 'active matching rule blocks matching source and injection argument',
    request: attackRequest,
    rules: [activeDeny],
    expected: true,
  },
  {
    name: 'expired rule allows request',
    request: attackRequest,
    rules: [{ ...activeDeny, expiresAt: '2026-10-17T11:59:59.000Z' }],
    expected: false,
  },
  {
    name: 'same source with normal request passes',
    request: { ...attackRequest, url: '/api/notes?search=weekly+notes' },
    rules: [activeDeny],
    expected: false,
  },
  {
    name: 'different source passes despite matching attack argument',
    request: { ...attackRequest, ip: '192.0.2.11' },
    rules: [activeDeny],
    expected: false,
  },
  {
    name: 'alert and record outcomes do not create active deny rules',
    request: attackRequest,
    rules: [
      { ...activeDeny, action: 'alert' },
      { ...activeDeny, action: 'record' },
    ],
    expected: false,
  },
];

for (const testCase of cases) {
  assert.equal(isDeniedByTemporaryRules(testCase.request, testCase.rules, patterns, now), testCase.expected, testCase.name);
}

console.log(`temporary-deny: ${cases.length} checks passed`);
