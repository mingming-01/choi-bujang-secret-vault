import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) {
    return response.status(500).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  }

  try {
    const supabase = createClient(supabaseUrl, secretKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false,
      },
    });
    const { data, error } = await supabase
      .from('learning_notes')
      .select('id, title, content')
      .order('id', { ascending: true });

    if (error || !Array.isArray(data)) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({ notes: data });
  } catch {
    // Do not expose or log configuration values or upstream error details.
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
