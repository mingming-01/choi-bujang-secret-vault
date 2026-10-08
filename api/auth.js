import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const BEARER_TOKEN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function readBody(request) {
  if (typeof request.body === 'string') {
    try { return JSON.parse(request.body); } catch { return null; }
  }
  return request.body;
}

function getAuthService() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) throw new Error('service_not_configured');

  const url = new URL(supabaseUrl);
  const issuer = new URL(config.identityProvider.issuer);
  if (url.protocol !== 'https:' || url.origin !== issuer.origin
      || (url.pathname !== '/' && url.pathname !== '') || url.username || url.password) {
    throw new Error('service_not_configured');
  }

  // Use a request-local client so concurrent logins cannot share mutable auth state.
  const supabase = createClient(url.origin, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const verifyLogin = createLoginVerifier({
    config,
    supabaseSecretKey: secretKey,
    supabaseClient: supabase,
  });
  return { supabase, verifyLogin };
}

function publicSession(session) {
  return {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    user: { email: session.user?.email ?? '' },
  };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['POST', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'POST, PUT, DELETE');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  let service;
  try {
    service = getAuthService();
  } catch {
    return response.status(500).json({ error: 'AUTH_SERVICE_UNAVAILABLE' });
  }

  if (request.method === 'POST') {
    const body = readBody(request);
    if (!body || typeof body.email !== 'string' || typeof body.password !== 'string'
        || body.email.length > 320 || body.password.length === 0 || body.password.length > 1024) {
      return response.status(400).json({ error: 'INVALID_LOGIN_REQUEST' });
    }

    try {
      const { data, error } = await service.supabase.auth.signInWithPassword({
        email: body.email.trim(),
        password: body.password,
      });
      if (error || !data.session) {
        return response.status(401).json({ error: 'INVALID_CREDENTIALS' });
      }
      return response.status(200).json({ session: publicSession(data.session) });
    } catch {
      return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
    }
  }

  if (request.method === 'PUT') {
    const body = readBody(request);
    if (!body || typeof body.refresh_token !== 'string'
        || body.refresh_token.length === 0 || body.refresh_token.length > 4096) {
      return response.status(400).json({ error: 'INVALID_REFRESH_REQUEST' });
    }

    try {
      const { data, error } = await service.supabase.auth.refreshSession({
        refresh_token: body.refresh_token,
      });
      if (error || !data.session) {
        return response.status(401).json({ error: 'INVALID_SESSION' });
      }
      return response.status(200).json({ session: publicSession(data.session) });
    } catch {
      return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
    }
  }

  const authorization = request.headers?.authorization;
  const match = typeof authorization === 'string' ? BEARER_TOKEN.exec(authorization) : null;
  if (!match) return response.status(401).json({ error: 'AUTHENTICATION_REQUIRED' });

  let user;
  try {
    user = await service.verifyLogin(authorization);
  } catch {
    return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
  }
  if (!user || user.kind !== 'student') {
    return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
  }

  try {
    const { error } = await service.supabase.auth.admin.signOut(match[1], 'local');
    if (error) return response.status(502).json({ error: 'LOGOUT_UNAVAILABLE' });
    return response.status(200).json({ ok: true });
  } catch {
    return response.status(502).json({ error: 'LOGOUT_UNAVAILABLE' });
  }
}
