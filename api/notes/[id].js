import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const BEARER_TOKEN = /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;
let service;

function getService() {
  if (service) return service;
  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) throw new Error('service_not_configured');
  const url = new URL(supabaseUrl);
  const issuer = new URL(config.identityProvider.issuer);
  if (url.protocol !== 'https:' || url.origin !== issuer.origin
      || (url.pathname !== '/' && url.pathname !== '') || url.username || url.password) {
    throw new Error('service_not_configured');
  }
  const supabase = createClient(url.origin, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const verifyLogin = createLoginVerifier({ config, supabaseSecretKey: secretKey, supabaseClient: supabase });
  service = { supabase, verifyLogin };
  return service;
}

function readBody(request) {
  if (typeof request.body === 'string') {
    try { return JSON.parse(request.body); } catch { return null; }
  }
  return request.body;
}

function validNote(body) {
  return body && typeof body === 'object' && !Array.isArray(body)
    && typeof body.title === 'string' && body.title.trim().length > 0
    && body.title.length <= 200 && typeof body.body === 'string' && body.body.length <= 20000;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return response.status(401).json({ error: 'AUTHENTICATION_REQUIRED' });
  }
  if (!BEARER_TOKEN.test(authorization)) {
    return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
  }

  let currentService;
  try {
    currentService = getService();
  } catch {
    return response.status(500).json({ error: 'NOTES_SERVICE_UNAVAILABLE' });
  }

  let user;
  try {
    user = await currentService.verifyLogin(authorization);
  } catch {
    return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
  }
  if (!user || user.kind !== 'student') {
    return response.status(401).json({ error: 'INVALID_AUTHENTICATION' });
  }
  const client = currentService.supabase;

  const id = request.query?.id;
  if (typeof id !== 'string' || !UUID.test(id)) {
    return response.status(400).json({ error: 'INVALID_NOTE_ID' });
  }

  if (request.method === 'GET') {
    try {
      const { data, error } = await client.from('user_notes')
        .select('id, title, content')
        .eq('id', id)
        .eq('owner_id', user.userId)
        .maybeSingle();
      if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
      return response.status(200).json({ id: data.id, title: data.title, body: data.content });
    } catch {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  }

  if (request.method === 'PUT') {
    const body = readBody(request);
    if (!validNote(body)) return response.status(400).json({ error: 'INVALID_NOTE' });
    try {
      const { data, error } = await client.from('user_notes')
        .update({ owner_id: user.userId, title: body.title.trim(), content: body.body })
        .eq('id', id)
        .eq('owner_id', user.userId)
        .select('id, title, content')
        .maybeSingle();
      if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
      return response.status(200).json({ id: data.id, title: data.title, body: data.content });
    } catch {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  }

  try {
    const { data, error } = await client.from('user_notes')
      .delete()
      .eq('id', id)
      .eq('owner_id', user.userId)
      .select('id')
      .maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    return response.status(200).json({ id: data.id });
  } catch {
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
