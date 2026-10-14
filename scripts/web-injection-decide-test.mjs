import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/web-injection/decide.mjs';

const decidePath = fileURLToPath(new URL('../xdr/web-injection/decide.mjs', import.meta.url));
const source = await readFile(decidePath, 'utf8');
assert.equal(/^\s*import\s/m.test(source), false, 'decide.mjs must have no imports');
assert.equal(/\b(?:readFile|writeFile|appendFile|fetch)\s*\(/.test(source), false, 'decide.mjs must not perform I/O');
assert.deepEqual([...source.matchAll(/export\s+(?:async\s+)?function\s+(\w+)/g)].map((match) => match[1]), ['decide'], 'decide must be the only public function');
assert.equal(/doc-(?:sql|script|up)-/.test(source), false, 'synthetic doc markers must not be attack patterns');

const fixturePath = fileURLToPath(new URL('../xdr/fixtures/web-injection.json', import.meta.url));
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const patternsPath = fileURLToPath(new URL('../xdr/web-injection/patterns.json', import.meta.url));
const webInjectionConfig = JSON.parse(await readFile(patternsPath, 'utf8'));
assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
assert.equal(fixture.moduleKey, 'web-injection');
assert.equal(webInjectionConfig.schema, 'aleph.xdr.web-injection-patterns.v1');

// High-risk metadata may request review, but cannot establish an attack or
// block. Description, count, marker and severity alone never establish attack.
const counts = { block: 0, alert: 0, record: 0 };
for (const alert of fixture.alerts) {
  const result = decide({ ...alert, webInjectionConfig });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason'], alert.id);
  const expected = alert.rule.level >= 10 && alert.rule.mitre.includes('T1190') ? 'alert' : 'record';
  assert.equal(result.action, expected, `${alert.id}: metadata can request review only; no request attack evidence`);
  assert.equal(typeof result.confidence, 'number', alert.id);
  assert.equal(typeof result.reason, 'string', alert.id);
  assert.ok(result.action !== 'block', alert.id);
  counts[result.action] += 1;

  const flattenedAlert = {
    ...alert,
    description: alert.rule.description,
    rule: { ...alert.rule, description: undefined },
    webInjectionConfig,
  };
  assert.equal(decide(flattenedAlert).action, result.action, `description does not change classification for ${alert.id}`);
}
assert.deepEqual(counts, { block: 0, alert: 8, record: 18 }, 'fixture direct-call classifications');

const sqlUrl = '/search?q=union+select+name+from+users';
const correlated = (id, url = sqlUrl, sourceAddress = 'ipv4:203.0.113.90', patternId = 'sql-injection') => ({
  id,
  data: { srcip: '203.0.113.90', url },
  webInjectionConfig,
  correlationEvidence: { sourceAddress, patternId, alertIds: [id, `${id}-peer`] },
});

const sqlAlert = {
  id: 'standalone-sql',
  data: { srcip: '203.0.113.90', url: sqlUrl, count: '99' },
  webInjectionConfig,
};
assert.equal(decide(sqlAlert).action, 'alert', 'one actual SQL pattern remains alert-only regardless of data.count');
assert.equal(decide({
  ...sqlAlert,
  rule: { description: '같은 주소에서 SQL 구문이 3번 반복됐습니다.' },
  data: { ...sqlAlert.data, count: '1' },
}).action, 'alert', 'description claims cannot establish repetition');
assert.equal(decide({
  data: { srcip: '203.0.113.90', url: '/search?q=doc-sql-chain', count: '3' },
  webInjectionConfig,
  rule: { level: 12, mitre: ['T1190'] },
}).action, 'alert', 'synthetic marker, count and high-risk metadata request review only, not block');
for (const word of ['select-course', 'script-class', 'up-notes', 'sql-class']) {
  assert.equal(decide({ data: { srcip: '203.0.113.90', url: `/search?q=${word}` }, webInjectionConfig }).action, 'record', `${word} alone is not an attack pattern`);
}

assert.equal(decide(correlated('sql-event-a')).action, 'block', 'two distinct same-source same-pattern alert IDs permit blocking');
assert.equal(decide({
  ...correlated('wrong-source'),
  data: { srcip: '198.51.100.90', url: sqlUrl },
}).action, 'alert', 'correlation evidence for another source cannot block');
assert.equal(decide({
  ...sqlAlert,
  id: 'duplicate-id',
  correlationEvidence: { sourceAddress: 'ipv4:203.0.113.90', patternId: 'sql-injection', alertIds: ['duplicate-id', 'duplicate-id'] },
}).action, 'alert', 'duplicate IDs do not prove separate alerts');
assert.equal(decide({
  ...correlated('wrong-pattern'),
  correlationEvidence: { ...correlated('wrong-pattern').correlationEvidence, patternId: 'script-tag' },
}).action, 'alert', 'correlation evidence for another pattern cannot block');
assert.equal(decide({
  ...correlated('extra-correlation-field'),
  correlationEvidence: { ...correlated('extra-correlation-field').correlationEvidence, count: 2 },
}).action, 'alert', 'unrecognized correlation fields are rejected');

const scriptUrl = '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E';
assert.equal(decide({ data: { srcip: '203.0.113.90', url: scriptUrl }, webInjectionConfig }).action, 'alert', 'one actual script tag remains alert-only');
assert.equal(decide(correlated('script-event', scriptUrl, 'ipv4:203.0.113.90', 'script-tag')).action, 'block', 'repeated same-source script-tag alerts may block');
const traversalUrl = '/files?path=../../etc/passwd';
assert.equal(decide({ data: { srcip: '203.0.113.90', url: traversalUrl }, webInjectionConfig }).action, 'alert', 'one actual traversal alert remains alert-only');
assert.equal(decide(correlated('traversal-event', traversalUrl, 'ipv4:203.0.113.90', 'path-traversal')).action, 'block', 'repeated same-source path-traversal alerts may block');
assert.equal(decide({ data: { srcip: '203.0.113.90', url: '/files?path=../etc/passwd' }, webInjectionConfig }).action, 'alert', 'a single ../ is an incomplete request signal and remains review-only');
assert.equal(decide({ data: { srcip: '203.0.113.90', url: "/search?q=person's-name" }, webInjectionConfig }).action, 'alert', 'a lone quote in actual request data is review-only');
assert.equal(decide({ data: { srcip: '203.0.113.90', url: '/search?q=union+select+name+from+users+%3Cscript%3E' }, webInjectionConfig }).action, 'alert', 'overlapping request patterns remain ambiguous');
assert.equal(decide({ data: { srcip: '203.0.113.90', url: '/search?q=select' }, webInjectionConfig }).action, 'alert', 'an incomplete injection-shaped SQL request is review-only');

assert.equal(decide({
  id: 'ipv6-a',
  data: { srcip: '2001:db8::1', url: sqlUrl },
  webInjectionConfig,
  correlationEvidence: { sourceAddress: 'ipv6:2001:0db8:0000:0000:0000:0000:0000:0001', patternId: 'sql-injection', alertIds: ['ipv6-a', 'ipv6-b'] },
}).action, 'block', 'valid IPv6 sources can be correlated');
assert.equal(decide({
  id: 'mapped-ipv6',
  data: { srcip: '::ffff:203.0.113.90', url: sqlUrl },
  webInjectionConfig,
  correlationEvidence: { sourceAddress: 'ipv6:0000:0000:0000:0000:0000:ffff:cb00:715a', patternId: 'sql-injection', alertIds: ['mapped-ipv6', 'mapped-peer'] },
}).action, 'block', 'IPv4-embedded IPv6 normalization matches the runner');
assert.equal(decide({
  id: 'invalid-ip',
  data: { srcip: '999.1.1.1', url: sqlUrl },
  webInjectionConfig,
  correlationEvidence: { sourceAddress: 'ipv4:999.1.1.1', patternId: 'sql-injection', alertIds: ['invalid-ip', 'peer'] },
}).action, 'alert', 'invalid source IPs cannot be blocked');

const customConfig = {
  ...webInjectionConfig,
  patterns: [{ id: 'custom-sql-probe', source: 'attack-token-xyz', flags: 'i' }],
  ambiguousPatterns: [],
};
assert.equal(decide({ data: { url: '/?q=attack-token-xyz' }, webInjectionConfig: customConfig }).action, 'alert', 'the runner-injected pattern config governs the real decision');
assert.equal(decide({ data: { url: '/?q=union+select+name+from+users' }, webInjectionConfig: customConfig }).action, 'record', 'configured patterns replace, rather than duplicate, hard-coded pattern lists');

console.log(`독립 decide 테스트 계약 확인: ${fixture.alerts.length}개 fixture와 요청·상관관계 경계 사례`);
console.log(`개별 fixture 직접 호출 집계: block ${counts.block} / alert ${counts.alert} / record ${counts.record}`);
