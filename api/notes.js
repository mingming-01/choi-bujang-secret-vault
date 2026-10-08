import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const BEARER_TOKEN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function hasValidJwtShape(authorization) {
  const match = authorization.match(BEARER_TOKEN);
  if (!match) return false;

  try {
    const [header, payload] = match[1].split('.');
    const decode = (value) =>
      JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));

    const decodedHeader = decode(header);
    const decodedPayload = decode(payload);

    return (
      decodedHeader &&
      typeof decodedHeader === 'object' &&
      !Array.isArray(decodedHeader) &&
      decodedPayload &&
      typeof decodedPayload === 'object' &&
      !Array.isArray(decodedPayload)
    );
  } catch {
    return false;
  }
}
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

async function authenticatedService(request) {
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return { error: 'AUTHENTICATION_REQUIRED', status: 401 };
  }
  if (!hasValidJwtShape(authorization)) {
    return { error: 'INVALID_AUTHENTICATION', status: 401 };
  }

  let service;
  try {
    service = getService();
  } catch {
    return { error: 'NOTES_SERVICE_UNAVAILABLE', status: 500 };
  }

  let user;
  try {
    user = await service.verifyLogin(authorization);
  } catch {
    return { error: 'INVALID_AUTHENTICATION', status: 401 };
  }
  if (!user || user.kind !== 'student') return { error: 'INVALID_AUTHENTICATION', status: 401 };
  return { ...service, user };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const auth = await authenticatedService(request);
  if (auth.error) return response.status(auth.status).json({ error: auth.error });
  const { supabase: client, user } = auth;

  if (request.method === 'GET') {
    try {
      const [
        { data: notes, error: notesError },
        { data: samples, error: samplesError },
      ] = await Promise.all([
        client.from('user_notes').select('id, title, content')
          .eq('owner_id', user.userId).order('created_at', { ascending: true }),
        client.from('learning_notes').select('id, title, content')
          .eq('owner_id', user.userId).order('id', { ascending: true }),
      ]);
      if (notesError || samplesError || !Array.isArray(notes) || !Array.isArray(samples)) {
        return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      }
      return response.status(200).json({
        notes: notes.map(note => ({ id: note.id, title: note.title, body: note.content })),
        samples,
      });
    } catch {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  }

  const body = readBody(request);
  if (!validNote(body)) return response.status(400).json({ error: 'INVALID_NOTE' });
  if (body.id !== undefined && (typeof body.id !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(body.id))) {
    return response.status(400).json({ error: 'INVALID_NOTE_ID' });
  }

  const id = body.id ?? randomUUID();
  try {
    const { data, error } = await client.from('user_notes').insert({
      id,
      owner_id: user.userId,
      title: body.title.trim(),
      content: body.body,
    }).select('id').single();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    return response.status(201).json({ id: data.id });
  } catch {
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
