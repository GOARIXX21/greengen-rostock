/**
 * GreenGenRostock V27 – Worker
 * - Liefert die bestehende HTML-App (Assets)
 * - D1 API für verschlüsselte State-Blobs
 * - Keine Klartextdaten, keine Login-Logik, keine Daten-Löschung
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS },
  });
}

async function ensureTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
}

async function handleApi(request, env) {
  if (!env.DB) {
    return json({ ok: false, error: 'D1 binding missing (DB)' }, 503);
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';

  try {
    await ensureTable(env.DB);

    // Health
    if (path === '/api/health' && request.method === 'GET') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM app_state').first();
      return json({ ok: true, d1: true, keys: row?.c ?? 0 });
    }

    // GET /api/state  → alle Keys (nur Metadaten + optional values)
    if (path === '/api/state' && request.method === 'GET') {
      const includeValues = url.searchParams.get('values') === '1';
      if (includeValues) {
        const { results } = await env.DB.prepare(
          'SELECT key, value, updated_at FROM app_state ORDER BY key'
        ).all();
        const map = {};
        for (const r of results || []) map[r.key] = { value: r.value, updated_at: r.updated_at };
        return json({ ok: true, data: map });
      }
      const { results } = await env.DB.prepare(
        'SELECT key, updated_at FROM app_state ORDER BY key'
      ).all();
      return json({ ok: true, keys: (results || []).map((r) => ({ key: r.key, updated_at: r.updated_at })) });
    }

    // GET /api/state/:key
    const getMatch = path.match(/^\/api\/state\/([^/]+)$/);
    if (getMatch && request.method === 'GET') {
      const key = decodeURIComponent(getMatch[1]);
      const row = await env.DB.prepare(
        'SELECT key, value, updated_at FROM app_state WHERE key = ?'
      ).bind(key).first();
      if (!row) return json({ ok: true, found: false, key, value: null });
      return json({ ok: true, found: true, key: row.key, value: row.value, updated_at: row.updated_at });
    }

    // PUT /api/state/:key
    // Body: { value: "<encrypted-string>", clientUpdatedAt?: "<ISO>" }
    // Vorhandener D1-Stand wird NUR überschrieben, wenn clientUpdatedAt
    // nachweislich >= vorhandenem updated_at ist. Fehlt/unklar → kein Update.
    if (getMatch && request.method === 'PUT') {
      const key = decodeURIComponent(getMatch[1]);
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: 'Invalid JSON body' }, 400);
      }
      if (typeof body?.value !== 'string') {
        return json({ ok: false, error: 'Body must contain string field "value"' }, 400);
      }

      const existing = await env.DB.prepare(
        'SELECT value, updated_at FROM app_state WHERE key = ?'
      ).bind(key).first();

      const now = new Date().toISOString();
      const clientTs = typeof body.clientUpdatedAt === 'string' ? body.clientUpdatedAt : null;
      const clientMs = clientTs ? Date.parse(clientTs) : NaN;

      if (!existing) {
        // Neu: anlegen
        const ts = (Number.isFinite(clientMs) ? new Date(clientMs).toISOString() : now);
        await env.DB.prepare(
          'INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?)'
        ).bind(key, body.value, ts).run();
        return json({ ok: true, key, updated_at: ts, created: true });
      }

      // Key existiert → nur updaten wenn Client nachweislich >= D1
      const existingMs = existing.updated_at ? Date.parse(existing.updated_at) : NaN;
      if (!Number.isFinite(clientMs) || !Number.isFinite(existingMs)) {
        // Unklar → vorhandenen D1-Wert behalten
        return json({
          ok: true,
          key,
          updated_at: existing.updated_at,
          skipped: true,
          reason: 'timestamp_unclear_keep_existing',
        });
      }
      if (clientMs < existingMs) {
        // Client älter → D1 behalten
        return json({
          ok: true,
          key,
          updated_at: existing.updated_at,
          skipped: true,
          reason: 'client_older_than_d1',
        });
      }

      // clientMs >= existingMs → Update erlaubt
      const ts = new Date(clientMs).toISOString();
      await env.DB.prepare(
        'UPDATE app_state SET value = ?, updated_at = ? WHERE key = ?'
      ).bind(body.value, ts, key).run();
      return json({ ok: true, key, updated_at: ts, updated: true });
    }

    // POST /api/migrate
    // Body: { items: { key: encryptedString | { value, clientUpdatedAt? }, ... } }
    // Strikt nicht-destruktiv: vorhandene Keys werden NIEMALS überschrieben.
    // Bei erstmaligem Insert: clientUpdatedAt (lokaler gg_meta) wenn gültig, sonst Serverzeit.
    if (path === '/api/migrate' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: 'Invalid JSON body' }, 400);
      }
      const items = body?.items;
      if (!items || typeof items !== 'object') {
        return json({ ok: false, error: 'Body must contain object "items"' }, 400);
      }
      const now = new Date().toISOString();
      let written = 0;
      let skipped = 0;
      const keys = Object.keys(items);
      for (const key of keys) {
        const raw = items[key];
        let value = null;
        let clientTs = null;
        if (typeof raw === 'string') {
          value = raw;
        } else if (raw && typeof raw === 'object' && typeof raw.value === 'string') {
          value = raw.value;
          if (typeof raw.clientUpdatedAt === 'string') clientTs = raw.clientUpdatedAt;
        } else {
          continue;
        }
        const existing = await env.DB.prepare(
          'SELECT key FROM app_state WHERE key = ?'
        ).bind(key).first();
        if (existing) {
          skipped++;
          continue; // vorhanden → unverändert lassen
        }
        const clientMs = clientTs ? Date.parse(clientTs) : NaN;
        const ts = Number.isFinite(clientMs) ? new Date(clientMs).toISOString() : now;
        await env.DB.prepare(
          'INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?)'
        ).bind(key, value, ts).run();
        written++;
      }
      return json({ ok: true, written, skipped, keys: keys.length, updated_at: now });
    }

    return json({ ok: false, error: 'Not found' }, 404);
  } catch (e) {
    console.error('[GG-D1]', e);
    return json({ ok: false, error: String(e?.message || e) }, 500);
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env);
    }

    // Statische App ausliefern
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('ASSETS binding missing – index.html not available', { status: 500 });
  },
};
