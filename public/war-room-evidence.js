export function createEvidenceRecord(input) {
  const {
    label, method, path, expectedStatus, expectedCode = null,
    responseStatus = null, responseCode = null, responseRequestId = null,
    clientRequestId, checkedAt, error = null,
  } = input;
  if (typeof label !== 'string' || typeof method !== 'string' || typeof path !== 'string'
      || !Number.isInteger(expectedStatus) || typeof clientRequestId !== 'string'
      || typeof checkedAt !== 'string') {
    throw new TypeError('invalid_evidence_record');
  }
  const requestIdSource = typeof responseRequestId === 'string' && responseRequestId
    ? 'server' : 'client';
  const requestId = requestIdSource === 'server' ? responseRequestId : clientRequestId;
  const actual = Number.isInteger(responseStatus)
    ? `HTTP ${responseStatus}${typeof responseCode === 'string' ? ` · ${responseCode}` : ''}`
    : `HTTP 응답 미확인${typeof error === 'string' && error ? ` · ${error}` : ''}`;
  let verdict = '미검증';
  if (Number.isInteger(responseStatus)) {
    verdict = responseStatus === expectedStatus
      && (!expectedCode || responseCode === expectedCode) ? '일치' : '불일치';
  }
  return {
    label, method, path,
    expected: `HTTP ${expectedStatus}${expectedCode ? ` · ${expectedCode}` : ''}`,
    actual, requestId, requestIdSource, checkedAt, verdict,
  };
}

export function summarizeEvidence(rows) {
  const summary = { total: rows.length, matched: 0, mismatched: 0, unverified: 0 };
  for (const row of rows) {
    if (row.verdict === '일치') summary.matched += 1;
    else if (row.verdict === '불일치') summary.mismatched += 1;
    else summary.unverified += 1;
  }
  return summary;
}
