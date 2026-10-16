import { createHash } from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const DIGEST = /^[A-Za-z0-9_-]{43}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digestText(value) {
  return createHash('sha256').update(value, 'utf8').digest('base64url');
}

function bodyDigest(body, method) {
  if (method === 'GET' || body === undefined || body === '') {
    return digestText('');
  }

  let value = body;
  if (typeof body === 'string') {
    try {
      value = JSON.parse(body);
    } catch {
      return digestText(body);
    }
  }
  return digestText(canonicalJson(value));
}

function webAuthnSettings(config) {
  const configuredOrigin = process.env.WEBAUTHN_ORIGIN || config.publicAppUrl;
  const originUrl = new URL(configuredOrigin);
  const rpID = process.env.WEBAUTHN_RP_ID || originUrl.hostname;

  if (!['https:', 'http:'].includes(originUrl.protocol)
      || (originUrl.protocol === 'http:' && originUrl.hostname !== 'localhost')
      || originUrl.username || originUrl.password
      || originUrl.pathname !== '/' && originUrl.pathname !== ''
      || originUrl.search || originUrl.hash
      || !rpID || rpID.includes('/') || rpID.includes(':')) {
    throw new Error('invalid_webauthn_origin');
  }

  return { origin: originUrl.origin, rpID };
}

function requestPath(request, origin) {
  const raw = request.url || request.originalUrl || '/';
  const url = new URL(raw, origin);
  if (url.origin !== origin || url.hash) return null;
  return `${url.pathname}${url.search}`;
}

function allowedTarget(method, path, origin) {
  if (typeof method !== 'string' || typeof path !== 'string' || path.length > 2048) {
    return false;
  }

  let url;
  try {
    url = new URL(path, origin);
  } catch {
    return false;
  }

  if (url.origin !== origin || url.hash || `${url.pathname}${url.search}` !== path) {
    return false;
  }

  if (url.pathname === '/api/notes') {
    return ['GET', 'POST'].includes(method);
  }

  if (url.pathname === '/api/operations') {
    return method === 'GET';
  }

  if (url.pathname === '/api/restore') {
    return method === 'POST';
  }

  if (/^\/api\/notes\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(url.pathname)) {
    return ['GET', 'PUT', 'DELETE'].includes(method);
  }

  return false;
}

function reply(status, body) {
  return { status, body };
}

async function getDevices(supabase, userId) {
  const { data, error } = await supabase.from('device_credentials')
    .select('id, device_label, status, created_at, approved_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });

  if (error || !Array.isArray(data)) {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }

  const devices = data.map(device => ({
    requestId: device.id,
    label: device.device_label,
    status: device.status,
    createdAt: device.created_at,
    approvedAt: device.approved_at,
  }));

  return reply(200, {
    devices,
    approved: devices.some(device => device.status === 'approved'),
  });
}

async function registrationOptions({ supabase, userId, config, body }) {
  const { data: existing, error } = await supabase.from('device_credentials')
    .select('credential_id, transports')
    .eq('user_id', userId)
    .in('status', ['pending', 'approved']);

  if (error || !Array.isArray(existing)) {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }

  let settings;
  let options;
  try {
    settings = webAuthnSettings(config);
    options = await generateRegistrationOptions({
      rpName: 'BYTE BACK 보호 자료실',
      rpID: settings.rpID,
      userID: new TextEncoder().encode(userId),
      userName: userId,
      userDisplayName: 'BYTE BACK 학생',
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      excludeCredentials: existing.map(item => ({
        id: item.credential_id,
        transports: item.transports || [],
      })),
    });
  } catch {
    return reply(503, { error: 'DEVICE_REGISTRATION_UNAVAILABLE' });
  }

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const { error: insertError } = await supabase.from('device_challenges').insert({
    user_id: userId,
    purpose: 'registration',
    challenge: options.challenge,
    expires_at: expiresAt,
  });

  if (insertError) {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }

  const requestedLabel = typeof body.deviceLabel === 'string'
    ? body.deviceLabel.trim().slice(0, 80)
    : '';

  return reply(200, {
    challenge: options.challenge,
    options,
    deviceLabel: requestedLabel || 'BYTE BACK 기기',
  });
}

async function consumeChallenge(supabase, id) {
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('device_challenges')
    .update({ used_at: now })
    .eq('id', id)
    .is('used_at', null)
    .gt('expires_at', now)
    .select('id')
    .maybeSingle();

  return !error && Boolean(data);
}

async function verifyRegistration({ supabase, userId, config, body }) {
  if (typeof body.challenge !== 'string' || !isObject(body.credential)) {
    return reply(400, { error: 'INVALID_DEVICE_REGISTRATION' });
  }

  const now = new Date().toISOString();
  const { data: pendingChallenge, error } = await supabase.from('device_challenges')
    .select('id, challenge')
    .eq('user_id', userId)
    .eq('purpose', 'registration')
    .eq('challenge', body.challenge)
    .is('used_at', null)
    .gt('expires_at', now)
    .maybeSingle();

  if (error || !pendingChallenge) {
    return reply(403, { error: 'INVALID_DEVICE_CHALLENGE' });
  }

  let verification;
  try {
    const settings = webAuthnSettings(config);
    verification = await verifyRegistrationResponse({
      response: body.credential,
      expectedChallenge: pendingChallenge.challenge,
      expectedOrigin: settings.origin,
      expectedRPID: settings.rpID,
      requireUserVerification: true,
    });
  } catch {
    return reply(403, { error: 'INVALID_DEVICE_REGISTRATION' });
  }

  if (!verification.verified || !verification.registrationInfo
      || !verification.registrationInfo.credential?.id
      || !(verification.registrationInfo.credential.publicKey instanceof Uint8Array)) {
    return reply(403, { error: 'INVALID_DEVICE_REGISTRATION' });
  }

  if (!await consumeChallenge(supabase, pendingChallenge.id)) {
    return reply(403, { error: 'INVALID_DEVICE_CHALLENGE' });
  }

  const credential = verification.registrationInfo.credential;
  const deviceLabel = typeof body.deviceLabel === 'string'
    ? body.deviceLabel.trim().slice(0, 80)
    : '';

  const { data: inserted, error: insertError } = await supabase.from('device_credentials')
    .insert({
      user_id: userId,
      credential_id: credential.id,
      public_key: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      transports: credential.transports || [],
      device_label: deviceLabel || 'BYTE BACK 기기',
      status: 'pending',
    })
    .select('id, device_label, status, created_at')
    .single();

  if (insertError || !inserted) {
    return reply(409, { error: 'DEVICE_REGISTRATION_CONFLICT' });
  }

  return reply(200, {
    device: {
      requestId: inserted.id,
      label: inserted.device_label,
      status: inserted.status,
      createdAt: inserted.created_at,
    },
    message: '기기 등록 요청을 접수했습니다. 서버 관리자의 승인을 기다려 주세요.',
  });
}

async function requestChallenge({ supabase, userId, config, body }) {
  const { method, path, bodySha256 } = body;
  let settings;

  try {
    settings = webAuthnSettings(config);
  } catch {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }

  if (!allowedTarget(method, path, settings.origin)
      || !DIGEST.test(bodySha256 || '')) {
    return reply(400, { error: 'INVALID_DEVICE_REQUEST' });
  }

  const { data: devices, error } = await supabase.from('device_credentials')
    .select('credential_id, transports')
    .eq('user_id', userId)
    .eq('status', 'approved');

  if (error || !Array.isArray(devices)) {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }
  if (!devices.length) {
    return reply(403, { error: 'DEVICE_NOT_APPROVED' });
  }

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID: settings.rpID,
      allowCredentials: devices.map(device => ({
        id: device.credential_id,
        transports: device.transports || [],
      })),
      userVerification: 'required',
      timeout: 60000,
    });
  } catch {
    return reply(503, { error: 'DEVICE_AUTHENTICATION_UNAVAILABLE' });
  }

  const { error: insertError } = await supabase.from('device_challenges').insert({
    user_id: userId,
    purpose: 'request',
    challenge: options.challenge,
    request_method: method,
    request_path: path,
    request_body_sha256: bodySha256,
    expires_at: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
  });

  if (insertError) {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }

  return reply(200, { options });
}

export async function handleDeviceAction(action, context) {
  try {
    switch (action) {
      case 'device-status':
        return await getDevices(context.supabase, context.userId);
      case 'device-registration-options':
        return await registrationOptions(context);
      case 'device-registration-verify':
        return await verifyRegistration(context);
      case 'device-challenge':
        return await requestChallenge(context);
      default:
        return reply(400, { error: 'UNKNOWN_DEVICE_ACTION' });
    }
  } catch {
    return reply(503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
  }
}

export async function verifyDeviceRequest(request, { supabase, userId, config }) {
  const challengeValue = request.headers?.['x-device-challenge'];
  const assertionValue = request.headers?.['x-device-assertion'];

  if (typeof challengeValue !== 'string' || !challengeValue
      || typeof assertionValue !== 'string' || assertionValue.length > 20000) {
    return { ok: false, status: 403, error: 'DEVICE_SIGNATURE_REQUIRED' };
  }

  let settings;
  let assertion;
  try {
    settings = webAuthnSettings(config);
    assertion = JSON.parse(Buffer.from(assertionValue, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_SIGNATURE' };
  }

  if (!isObject(assertion) || typeof assertion.id !== 'string'
      || typeof assertion.rawId !== 'string' || !isObject(assertion.response)) {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_SIGNATURE' };
  }

  const now = new Date().toISOString();
  const { data: pending, error } = await supabase.from('device_challenges')
    .select('*')
    .eq('user_id', userId)
    .eq('purpose', 'request')
    .eq('challenge', challengeValue)
    .is('used_at', null)
    .gt('expires_at', now)
    .maybeSingle();

  if (error || !pending) {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_CHALLENGE' };
  }

  const actualPath = requestPath(request, settings.origin);
  if (pending.request_method !== request.method
      || pending.request_path !== actualPath
      || pending.request_body_sha256 !== bodyDigest(request.body, request.method)
      || !allowedTarget(request.method, actualPath, settings.origin)) {
    return { ok: false, status: 403, error: 'SIGNED_REQUEST_MISMATCH' };
  }

  const { data: credential, error: credentialError } = await supabase.from('device_credentials')
    .select('id, credential_id, public_key, counter, transports')
    .eq('user_id', userId)
    .eq('credential_id', assertion.id)
    .eq('status', 'approved')
    .maybeSingle();

  if (credentialError || !credential || assertion.rawId !== credential.credential_id) {
    return { ok: false, status: 403, error: 'DEVICE_NOT_APPROVED' };
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: pending.challenge,
      expectedOrigin: settings.origin,
      expectedRPID: settings.rpID,
      requireUserVerification: true,
      credential: {
        id: credential.credential_id,
        publicKey: new Uint8Array(Buffer.from(credential.public_key, 'base64url')),
        counter: Number(credential.counter),
        transports: credential.transports || [],
      },
    });
  } catch {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_SIGNATURE' };
  }

  if (!verification.verified) {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_SIGNATURE' };
  }

  // Atomically consume the one-time challenge before allowing the request.
  if (!await consumeChallenge(supabase, pending.id)) {
    return { ok: false, status: 403, error: 'INVALID_DEVICE_CHALLENGE' };
  }

  const nextCounter = verification.authenticationInfo.newCounter;
  const previousCounter = Number(credential.counter);
  if (nextCounter > previousCounter) {
    const { data: updated, error: updateError } = await supabase.from('device_credentials')
      .update({ counter: nextCounter })
      .eq('id', credential.id)
      .eq('counter', previousCounter)
      .select('id')
      .maybeSingle();

    if (updateError || !updated) {
      return { ok: false, status: 403, error: 'INVALID_DEVICE_SIGNATURE' };
    }
  }

  return { ok: true };
}
