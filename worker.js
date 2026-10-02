/**
 * GreenGenRostock V38-COMPLIANCE-HARDENED-APPEND-ONLY – Worker
 *
 * Cloudflare Secrets:
 *   AUTH_SIGNING_SECRET       optional – HMAC für Sitzungstokens
 *   MASTER_USER               bestehender Master-Benutzername
 *   MASTER_PASS               bestehendes Master-Passwort
 *   DATA_CRYPTO_PASSPHRASE    bestehende Daten-Hülle (nicht das Login)
 *
 * WICHTIG:
 * - MASTER_USER / MASTER_PASS werden nicht geändert.
 * - AUTH_SIGNING_SECRET ist optional.
 * - Falls AUTH_SIGNING_SECRET nicht vorhanden ist, wird für die
 *   Session-Signatur deterministisch aus bestehenden Secrets abgeleitet.
 * - Bestehende D1-Daten werden nicht gelöscht.
 * - Audit- und Zutrittsprotokolle sind append-only.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const SENSITIVE_KEYS = new Set([
  'gg_master_account',
  'vereinAdmins',
  'adminSystemInitialisiert',
  'vereinMitglieder',
  'vereinReservierungen',
  'vereinUmsatz',
  'vereinProtokolle',
  'vereinKassenbons',
  'vereinAudit',
  'vereinGuthabenHistorie',
  'vereinZutritte',
  'vereinPraevention',
  'vereinQualitaetspruefungen',
  'vereinRueckrufe',
  'vereinKcang26'
]);

const PUBLIC_GET_KEYS = new Set([
  'vereinNews',
  'vereinSorten',
  'vereinWissen',
  'vereinInfoArtikel',
  'vereinAbholzeitfenster',
  'standortKoordinaten',
  'vereinSepaSichtbar',
  'vereinUiEinstellungen'
]);

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const PBKDF_SALT = 'green-gen-rostock-salt-v1';

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
      ...extraHeaders
    },
  });
}

function b64urlEncode(bytes) {
  let bin = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);

  for (let i = 0; i < arr.length; i++) {
    bin += String.fromCharCode(arr[i]);
  }

  return btoa(bin)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function b64urlDecode(str) {
  const pad = str.length % 4 === 0
    ? ''
    : '='.repeat(4 - (str.length % 4));

  const b64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    + pad;

  const bin = atob(b64);
  const out = new Uint8Array(bin.length);

  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }

  return out;
}

function safeEq(a, b) {
  const s1 = String(a || '');
  const s2 = String(b || '');

  const n = Math.max(s1.length, s2.length, 1);

  let diff = s1.length ^ s2.length;

  for (let i = 0; i < n; i++) {
    diff |=
      (s1.charCodeAt(i) || 0) ^
      (s2.charCodeAt(i) || 0);
  }

  return diff === 0;
}

async function hmacSign(secret, msg) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(String(secret)),
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(msg)
  );

  return b64urlEncode(sig);
}

async function hmacVerify(secret, msg, sigB64) {
  try {
    return safeEq(
      await hmacSign(secret, msg),
      sigB64
    );
  } catch {
    return false;
  }
}

async function mintToken(secret, payload) {
  const body = b64urlEncode(
    new TextEncoder().encode(
      JSON.stringify(payload)
    )
  );

  return body + '.' + await hmacSign(secret, body);
}

async function readToken(secret, token) {
  if (
    !token ||
    typeof token !== 'string' ||
    token.indexOf('.') < 0
  ) {
    return null;
  }

  const [body, sig] = token.split('.');

  if (!body || !sig) {
    return null;
  }

  if (!(await hmacVerify(secret, body, sig))) {
    return null;
  }

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(
        b64urlDecode(body)
      )
    );

    if (
      !payload ||
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return null;
    }

    if (!payload.role || !payload.user) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function bearerToken(request) {
  const h = request.headers.get('Authorization') || '';

  const m = h.match(/^Bearer\s+(.+)$/i);

  if (m) {
    return m[1].trim();
  }

  const cookie = request.headers.get('Cookie') || '';

  const cm = cookie.match(
    /(?:^|;\s*)gg_session=([^;]+)/
  );

  return cm
    ? decodeURIComponent(cm[1])
    : '';
}

function getAuthSigningSecret(env) {
  /*
   * Bestehende Installation beibehalten:
   *
   * 1. Wenn AUTH_SIGNING_SECRET vorhanden ist:
   *    Dieses wird verwendet.
   *
   * 2. Wenn AUTH_SIGNING_SECRET NICHT vorhanden ist:
   *    Kein neuer Secret-Eintrag ist notwendig.
   *
   *    Stattdessen wird der Signierschlüssel aus bereits vorhandenen
   *    serverseitigen Secrets abgeleitet.
   *
   *    MASTER_USER / MASTER_PASS / DATA_CRYPTO_PASSPHRASE
   *    werden dabei NICHT verändert.
   */

  if (env.AUTH_SIGNING_SECRET) {
    return String(env.AUTH_SIGNING_SECRET);
  }

  const seed =
    env.MASTER_PASS ||
    env.DATA_CRYPTO_PASSPHRASE ||
    '';

  if (!seed) {
    return '';
  }

  return (
    'GG-AUTH-SIGNING-V1|' +
    String(env.MASTER_USER || '') +
    '|' +
    String(seed)
  );
}

function authConfigured(env) {
  const signingSecret = getAuthSigningSecret(env);

  return !!(
    signingSecret &&
    (
      env.MASTER_USER ||
      env.MASTER_PASS ||
      env.DATA_CRYPTO_PASSPHRASE
    )
  );
}

async function requireSession(request, env, roles) {
  const signingSecret = getAuthSigningSecret(env);

  if (!signingSecret) {
    return {
      ok: false,
      status: 503,
      error: 'auth_not_configured'
    };
  }

  const payload = await readToken(
    signingSecret,
    bearerToken(request)
  );

  if (!payload) {
    return {
      ok: false,
      status: 401,
      error: 'invalid_session'
    };
  }

  if (
    roles &&
    roles.length &&
    !roles.includes(payload.role)
  ) {
    return {
      ok: false,
      status: 403,
      error: 'forbidden'
    };
  }

  return {
    ok: true,
    session: payload
  };
}

async function decryptClientBlob(b64, passphrase) {
  if (!b64 || !passphrase) {
    return null;
  }

  try {
    const binStr = atob(String(b64));

    const bytes = new Uint8Array(binStr.length);

    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }

    if (bytes.length < 13) {
      try {
        return JSON.parse(binStr);
      } catch {
        return null;
      }
    }

    const iv = bytes.slice(0, 12);
    const data = bytes.slice(12);

    const enc = new TextEncoder();

    const keyMaterial =
      await crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
      );

    const key =
      await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: enc.encode(PBKDF_SALT),
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: 'AES-GCM',
          length: 256
        },
        false,
        ['decrypt']
      );

    const plain =
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv
        },
        key,
        data
      );

    return JSON.parse(
      new TextDecoder().decode(plain)
    );
  } catch {
    try {
      return JSON.parse(String(b64));
    } catch {
      return null;
    }
  }
}

async function loadStateValue(db, key) {
  const row =
    await db
      .prepare(
        'SELECT value FROM app_state WHERE key = ?'
      )
      .bind(key)
      .first();

  return row &&
    typeof row.value === 'string'
    ? row.value
    : null;
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

async function ensureAccessTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS access_events (
      id TEXT PRIMARY KEY NOT NULL,
      occurred_at TEXT NOT NULL,
      payload TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_access_events_occurred
    ON access_events(occurred_at)
  `).run();
}

async function ensureAuditTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY NOT NULL,
      occurred_at TEXT NOT NULL,
      payload TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE INDEX IF NOT EXISTS
    idx_audit_events_occurred
    ON audit_events(occurred_at)
  `).run();
}

async function sha256Hex(text) {
  const bytes =
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(
        String(text)
      )
    );

  return Array
    .from(new Uint8Array(bytes))
    .map(
      b => b.toString(16).padStart(2, '0')
    )
    .join('');
}

async function encryptClientBlob(value, passphrase) {
  if (!passphrase) {
    return null;
  }

  const enc = new TextEncoder();

  const keyMaterial =
    await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

  const key =
    await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode(PBKDF_SALT),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt']
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const plain =
    enc.encode(
      JSON.stringify(value)
    );

  const cipher =
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key,
      plain
    );

  const out =
    new Uint8Array(
      iv.length + cipher.byteLength
    );

  out.set(iv, 0);

  out.set(
    new Uint8Array(cipher),
    iv.length
  );

  let bin = '';

  for (const b of out) {
    bin += String.fromCharCode(b);
  }

  return btoa(bin);
}

async function migrateLegacyAuditOnce(db, env) {
  const marker =
    await db
      .prepare(
        "SELECT id FROM audit_events WHERE id = 'GG_LEGACY_MIGRATION_MARKER'"
      )
      .first();

  if (marker) {
    return;
  }

  const raw =
    await loadStateValue(
      db,
      'vereinAudit'
    );

  if (
    raw &&
    env.DATA_CRYPTO_PASSPHRASE
  ) {
    const legacy =
      await decryptClientBlob(
        raw,
        env.DATA_CRYPTO_PASSPHRASE
      );

    if (Array.isArray(legacy)) {
      for (const event of legacy) {
        const id =
          String(
            event?.id ||
            (
              Date.now() +
              '-' +
              crypto.randomUUID()
            )
          );

        const occurred =
          new Date(
            event?.date &&
            !Number.isNaN(
              Date.parse(event.date)
            )
              ? event.date
              : Date.now()
          ).toISOString();

        const payload =
          await encryptClientBlob(
            event,
            env.DATA_CRYPTO_PASSPHRASE
          );

        if (!payload) {
          continue;
        }

        const hash =
          await sha256Hex(payload);

        await db
          .prepare(`
            INSERT OR IGNORE INTO audit_events
            (
              id,
              occurred_at,
              payload,
              payload_sha256
            )
            VALUES (?, ?, ?, ?)
          `)
          .bind(
            id,
            occurred,
            payload,
            hash
          )
          .run();
      }
    }
  }

  await db
    .prepare(`
      INSERT OR IGNORE INTO audit_events
      (
        id,
        occurred_at,
        payload,
        payload_sha256
      )
      VALUES
      (
        'GG_LEGACY_MIGRATION_MARKER',
        ?,
        '',
        'migration-marker'
      )
    `)
    .bind(
      new Date().toISOString()
    )
    .run();
}

async function migrateLegacyAccessOnce(db, env) {
  const marker =
    await db
      .prepare(
        "SELECT id FROM access_events WHERE id = 'GG_LEGACY_ACCESS_MIGRATION_MARKER'"
      )
      .first();

  if (marker) {
    return;
  }

  const raw =
    await loadStateValue(
      db,
      'vereinZutritte'
    );

  if (
    raw &&
    env.DATA_CRYPTO_PASSPHRASE
  ) {
    const legacy =
      await decryptClientBlob(
        raw,
        env.DATA_CRYPTO_PASSPHRASE
      );

    if (Array.isArray(legacy)) {
      for (const event of legacy) {
        const id =
          String(
            event?.id ||
            (
              Date.now() +
              '-' +
              crypto.randomUUID()
            )
          );

        const occurred =
          new Date(
            event?.ts ||
            Date.now()
          ).toISOString();

        const payload =
          await encryptClientBlob(
            event,
            env.DATA_CRYPTO_PASSPHRASE
          );

        if (!payload) {
          continue;
        }

        const hash =
          await sha256Hex(payload);

        await db
          .prepare(`
            INSERT OR IGNORE INTO access_events
            (
              id,
              occurred_at,
              payload,
              payload_sha256
            )
            VALUES (?, ?, ?, ?)
          `)
          .bind(
            id,
            occurred,
            payload,
            hash
          )
          .run();
      }
    }
  }

  await db
    .prepare(`
      INSERT OR IGNORE INTO access_events
      (
        id,
        occurred_at,
        payload,
        payload_sha256
      )
      VALUES
      (
        'GG_LEGACY_ACCESS_MIGRATION_MARKER',
        ?,
        '',
        'migration-marker'
      )
    `)
    .bind(
      new Date().toISOString()
    )
    .run();
}

async function verifyMasterAgainstD1(
  env,
  user,
  pass
) {
  const phrase =
    env.DATA_CRYPTO_PASSPHRASE;

  if (!phrase || !env.DB) {
    return false;
  }

  const raw =
    await loadStateValue(
      env.DB,
      'gg_master_account'
    );

  if (!raw) {
    return false;
  }

  const master =
    await decryptClientBlob(
      raw,
      phrase
    );

  if (
    !master ||
    typeof master !== 'object'
  ) {
    return false;
  }

  const mu =
    master.user ||
    master.username ||
    '';

  const mp =
    master.pass ||
    master.password ||
    '';

  const role =
    String(
      master.role ||
      'MASTER'
    ).toUpperCase();

  if (
    role &&
    role !== 'MASTER'
  ) {
    return false;
  }

  return (
    safeEq(mu, user) &&
    safeEq(mp, pass)
  );
}

async function verifyAdminAgainstD1(
  env,
  user,
  pass
) {
  const phrase =
    env.DATA_CRYPTO_PASSPHRASE;

  if (!phrase || !env.DB) {
    return false;
  }

  const raw =
    await loadStateValue(
      env.DB,
      'vereinAdmins'
    );

  if (!raw) {
    return false;
  }

  const admins =
    await decryptClientBlob(
      raw,
      phrase
    );

  if (!Array.isArray(admins)) {
    return false;
  }

  return admins.some(
    a =>
      a &&
      safeEq(a.user, user) &&
      safeEq(a.pass, pass) &&
      String(
        a.role || 'ADMIN'
      ).toUpperCase() !== 'MASTER'
  );
}

async function isSystemInitialized(env) {
  if (!env.DB) {
    return false;
  }

  if (
    await env.DB
      .prepare(
        'SELECT key FROM app_state WHERE key = ?'
      )
      .bind('gg_master_account')
      .first()
  ) {
    return true;
  }

  if (
    await env.DB
      .prepare(
        'SELECT key FROM app_state WHERE key = ?'
      )
      .bind('adminSystemInitialisiert')
      .first()
  ) {
    return true;
  }

  return false;
}

async function handleAuth(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname.replace(
      /\/+$/,
      ''
    ) || '/';

  if (
    path === '/api/auth/login' &&
    request.method === 'POST'
  ) {
    if (!authConfigured(env)) {
      return json(
        {
          ok: false,
          error: 'auth_not_configured'
        },
        503
      );
    }

    let body;

    try {
      body =
        await request.json();
    } catch {
      return json(
        {
          ok: false,
          error: 'Invalid JSON body'
        },
        400
      );
    }

    const user =
      String(
        body?.user || ''
      ).trim();

    const pass =
      String(
        body?.pass || ''
      );

    if (!user || !pass) {
      return json(
        {
          ok: false,
          error: 'invalid'
        },
        401
      );
    }

    let role = null;

    const initialized =
      await isSystemInitialized(env);

    /*
     * Der alte einmalige Bootstrap-Zugang bleibt erhalten,
     * wird aber nach der Initialisierung deaktiviert.
     */

    if (
      !initialized &&
      safeEq(
        user,
        'admin'
      ) &&
      safeEq(
        pass,
        'vorstand2026'
      )
    ) {
      role = 'BOOTSTRAP';

    } else if (
      initialized &&
      safeEq(
        user,
        'admin'
      ) &&
      safeEq(
        pass,
        'vorstand2026'
      )
    ) {
      return json(
        {
          ok: false,
          error: 'bootstrap_disabled'
        },
        401
      );
    }

    /*
     * 1. Bestehender Cloudflare-Master
     */
    if (
      !role &&
      env.MASTER_USER &&
      env.MASTER_PASS &&
      safeEq(
        user,
        env.MASTER_USER
      ) &&
      safeEq(
        pass,
        env.MASTER_PASS
      )
    ) {
      role = 'MASTER';
    }

    /*
     * 2. Bestehender Master aus D1
     */
    if (!role) {
      if (
        await verifyMasterAgainstD1(
          env,
          user,
          pass
        )
      ) {
        role = 'MASTER';
      }
    }

    /*
     * 3. Bestehender Admin aus D1
     */
    if (!role) {
      if (
        await verifyAdminAgainstD1(
          env,
          user,
          pass
        )
      ) {
        role = 'ADMIN';
      }
    }

    if (!role) {
      return json(
        {
          ok: false,
          error: 'invalid'
        },
        401
      );
    }

    const now =
      Date.now();

    const payload = {
      user,
      role,
      iat: now,
      exp:
        now +
        SESSION_TTL_MS
    };

    const token =
      await mintToken(
        getAuthSigningSecret(env),
        payload
      );

    const cookie =
      `gg_session=${encodeURIComponent(token)}; ` +
      `Path=/; ` +
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}; ` +
      `HttpOnly; ` +
      `SameSite=Strict`;

    return json(
      {
        ok: true,
        user,
        role,
        token,
        exp: payload.exp,
        immutable:
          role === 'MASTER'
      },
      200,
      {
        'Set-Cookie': cookie
      }
    );
  }

  if (
    path === '/api/auth/session' &&
    request.method === 'GET'
  ) {
    const signingSecret =
      getAuthSigningSecret(env);

    if (!signingSecret) {
      return json(
        {
          ok: false,
          error: 'auth_not_configured'
        },
        503
      );
    }

    const payload =
      await readToken(
        signingSecret,
        bearerToken(request)
      );

    if (!payload) {
      return json(
        {
          ok: false,
          error: 'invalid_session'
        },
        401
      );
    }

    return json({
      ok: true,
      user: payload.user,
      role: payload.role,
      exp: payload.exp,
      immutable:
        payload.role === 'MASTER'
    });
  }

  if (
    path === '/api/auth/logout' &&
    request.method === 'POST'
  ) {
    return json(
      {
        ok: true
      },
      200,
      {
        'Set-Cookie':
          'gg_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'
      }
    );
  }

  return null;
}

async function handleApi(
  request,
  env
) {
  const authResp =
    await handleAuth(
      request,
      env
    );

  if (authResp) {
    return authResp;
  }

  if (!env.DB) {
    return json(
      {
        ok: false,
        error:
          'D1 binding missing (DB)'
      },
      503
    );
  }

  const url =
    new URL(request.url);

  const path =
    url.pathname.replace(
      /\/+$/,
      ''
    ) || '/';

  try {
    /*
     * Bestehende Tabelle sicherstellen.
     * CREATE IF NOT EXISTS verändert keine vorhandenen Daten.
     */
    await ensureTable(env.DB);

    /*
     * Append-only Protokolltabellen.
     */
    await ensureAuditTable(env.DB);
    await ensureAccessTable(env.DB);

    /*
     * Einmalige Migration vorhandener Protokolle.
     */
    await migrateLegacyAuditOnce(
      env.DB,
      env
    );

    await migrateLegacyAccessOnce(
      env.DB,
      env
    );

    /*
     * =========================================================
     * ZUTRITTSPROTOKOLL
     * =========================================================
     */

    if (
      path === '/api/access' &&
      request.method === 'GET'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      const limitRaw =
        Number(
          url.searchParams.get(
            'limit'
          ) || 1000
        );

      const limit =
        Math.min(
          Math.max(
            Number.isFinite(limitRaw)
              ? Math.floor(limitRaw)
              : 1000,
            1
          ),
          2000
        );

      const before =
        url.searchParams.get(
          'before'
        );

      let query =
        'SELECT id, occurred_at, payload, payload_sha256 ' +
        'FROM access_events ' +
        'WHERE id != ?';

      const binds = [
        'GG_LEGACY_ACCESS_MIGRATION_MARKER'
      ];

      if (before) {
        query +=
          ' AND occurred_at < ?';

        binds.push(before);
      }

      query +=
        ' ORDER BY occurred_at DESC LIMIT ?';

      binds.push(limit);

      const { results } =
        await env.DB
          .prepare(query)
          .bind(...binds)
          .all();

      return json({
        ok: true,
        entries:
          results || [],
        immutable: true,
        has_delete_endpoint:
          false,
        next_before:
          (
            results &&
            results.length === limit
          )
            ? results[
                results.length - 1
              ].occurred_at
            : null
      });
    }

    if (
      path === '/api/access' &&
      request.method === 'POST'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN',
            'BOOTSTRAP'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            ok: false,
            error:
              'Invalid JSON body'
          },
          400
        );
      }

      const id =
        String(
          body?.id || ''
        ).trim();

      const occurred =
        String(
          body?.occurred_at || ''
        ).trim();

      const payload =
        String(
          body?.payload || ''
        ).trim();

      if (
        !id ||
        !payload ||
        !occurred ||
        !Number.isFinite(
          Date.parse(occurred)
        )
      ) {
        return json(
          {
            ok: false,
            error:
              'invalid_access_event'
          },
          400
        );
      }

      const hash =
        await sha256Hex(
          payload
        );

      const exists =
        await env.DB
          .prepare(
            'SELECT id FROM access_events WHERE id = ?'
          )
          .bind(id)
          .first();

      if (exists) {
        return json({
          ok: true,
          appended: true,
          duplicate: true,
          id
        });
      }

      await env.DB
        .prepare(`
          INSERT INTO access_events
          (
            id,
            occurred_at,
            payload,
            payload_sha256
          )
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          id,
          new Date(
            occurred
          ).toISOString(),
          payload,
          hash
        )
        .run();

      return json({
        ok: true,
        appended: true,
        id,
        immutable: true
      });
    }

    /*
     * Zutrittsprotokolle können NICHT per PUT/PATCH/DELETE
     * verändert oder gelöscht werden.
     */
    if (
      path === '/api/access' &&
      (
        request.method === 'PUT' ||
        request.method === 'DELETE' ||
        request.method === 'PATCH'
      )
    ) {
      return json(
        {
          ok: false,
          error:
            'access_immutable',
          message:
            'Zutrittsprotokolle sind append-only und können nicht geändert oder gelöscht werden.'
        },
        405
      );
    }

    /*
     * =========================================================
     * AUDIT-PROTOKOLL
     * =========================================================
     */

    if (
      path === '/api/audit' &&
      request.method === 'GET'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      const limitRaw =
        Number(
          url.searchParams.get(
            'limit'
          ) || 1000
        );

      const limit =
        Math.min(
          Math.max(
            Number.isFinite(limitRaw)
              ? Math.floor(limitRaw)
              : 1000,
            1
          ),
          5000
        );

      const before =
        url.searchParams.get(
          'before'
        );

      let query =
        'SELECT id, occurred_at, payload, payload_sha256 ' +
        'FROM audit_events ' +
        'WHERE id != ?';

      const binds = [
        'GG_LEGACY_MIGRATION_MARKER'
      ];

      if (before) {
        query +=
          ' AND occurred_at < ?';

        binds.push(before);
      }

      query +=
        ' ORDER BY occurred_at DESC LIMIT ?';

      binds.push(limit);

      const { results } =
        await env.DB
          .prepare(query)
          .bind(...binds)
          .all();

      return json({
        ok: true,
        entries:
          results || [],
        immutable: true,
        has_delete_endpoint:
          false,
        next_before:
          (
            results &&
            results.length === limit
          )
            ? results[
                results.length - 1
              ].occurred_at
            : null
      });
    }

    if (
      path === '/api/audit' &&
      request.method === 'POST'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN',
            'BOOTSTRAP'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            ok: false,
            error:
              'Invalid JSON body'
          },
          400
        );
      }

      const id =
        String(
          body?.id || ''
        ).trim();

      const occurred =
        String(
          body?.occurred_at || ''
        ).trim();

      const payload =
        String(
          body?.payload || ''
        ).trim();

      if (
        !id ||
        !payload ||
        !occurred ||
        !Number.isFinite(
          Date.parse(occurred)
        )
      ) {
        return json(
          {
            ok: false,
            error:
              'invalid_audit_event'
          },
          400
        );
      }

      const hash =
        await sha256Hex(
          payload
        );

      const exists =
        await env.DB
          .prepare(
            'SELECT id FROM audit_events WHERE id = ?'
          )
          .bind(id)
          .first();

      if (exists) {
        return json({
          ok: true,
          appended: true,
          duplicate: true,
          id
        });
      }

      await env.DB
        .prepare(`
          INSERT INTO audit_events
          (
            id,
            occurred_at,
            payload,
            payload_sha256
          )
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          id,
          new Date(
            occurred
          ).toISOString(),
          payload,
          hash
        )
        .run();

      return json({
        ok: true,
        appended: true,
        id,
        immutable: true
      });
    }

    /*
     * Audit-Protokolle können NICHT verändert oder gelöscht werden.
     */
    if (
      path === '/api/audit' &&
      (
        request.method === 'PUT' ||
        request.method === 'DELETE' ||
        request.method === 'PATCH'
      )
    ) {
      return json(
        {
          ok: false,
          error:
            'audit_immutable',
          message:
            'Audit-Einträge sind append-only und können nicht geändert oder gelöscht werden.'
        },
        405
      );
    }

    /*
     * =========================================================
     * HEALTH
     * =========================================================
     */

    if (
      path === '/api/health' &&
      request.method === 'GET'
    ) {
      const row =
        await env.DB
          .prepare(
            'SELECT COUNT(*) AS c FROM app_state'
          )
          .first();

      return json({
        ok: true,
        d1: true,
        keys:
          row?.c ?? 0,
        auth:
          authConfigured(env)
      });
    }

    /*
     * =========================================================
     * KOMPLETTER STATE
     * =========================================================
     */

    if (
      path === '/api/state' &&
      request.method === 'GET'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN',
            'BOOTSTRAP'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      const includeValues =
        url.searchParams.get(
          'values'
        ) === '1';

      if (includeValues) {
        const { results } =
          await env.DB
            .prepare(
              'SELECT key, value, updated_at FROM app_state ORDER BY key'
            )
            .all();

        const map = {};

        for (const r of results || []) {
          if (
            r.key ===
            'gg_master_account'
          ) {
            map[r.key] = {
              value: null,
              updated_at:
                r.updated_at,
              redacted: true
            };
          } else {
            map[r.key] = {
              value:
                r.value,
              updated_at:
                r.updated_at
            };
          }
        }

        return json({
          ok: true,
          data: map
        });
      }

      const { results } =
        await env.DB
          .prepare(
            'SELECT key, updated_at FROM app_state ORDER BY key'
          )
          .all();

      return json({
        ok: true,
        keys:
          (
            results || []
          ).map(
            r => ({
              key:
                r.key,
              updated_at:
                r.updated_at
            })
          )
      });
    }

    /*
     * =========================================================
     * EINZELNER STATE
     * =========================================================
     */

    const getMatch =
      path.match(
        /^\/api\/state\/([^/]+)$/
      );

    if (
      getMatch &&
      request.method === 'GET'
    ) {
      const key =
        decodeURIComponent(
          getMatch[1]
        );

      /*
       * Öffentliche Keys dürfen ohne Session gelesen werden.
       * Alle anderen benötigen Auth.
       */
      if (
        !PUBLIC_GET_KEYS.has(key)
      ) {
        const gate =
          await requireSession(
            request,
            env,
            [
              'MASTER',
              'ADMIN',
              'BOOTSTRAP'
            ]
          );

        if (!gate.ok) {
          return json(
            {
              ok: false,
              error: gate.error
            },
            gate.status
          );
        }

        /*
         * Master-Konto niemals an normale Admins ausgeben.
         */
        if (
          key ===
            'gg_master_account' &&
          gate.session.role !==
            'MASTER' &&
          gate.session.role !==
            'BOOTSTRAP'
        ) {
          return json(
            {
              ok: false,
              error: 'forbidden'
            },
            403
          );
        }
      }

      const row =
        await env.DB
          .prepare(
            'SELECT key, value, updated_at FROM app_state WHERE key = ?'
          )
          .bind(key)
          .first();

      if (!row) {
        return json({
          ok: true,
          found: false,
          key,
          value: null
        });
      }

      /*
       * Master-Wert niemals ausgeben.
       */
      if (
        key ===
        'gg_master_account'
      ) {
        return json({
          ok: true,
          found: true,
          key,
          value: null,
          redacted: true,
          updated_at:
            row.updated_at
        });
      }

      return json({
        ok: true,
        found: true,
        key:
          row.key,
        value:
          row.value,
        updated_at:
          row.updated_at
      });
    }

    /*
     * =========================================================
     * STATE SPEICHERN
     * =========================================================
     */

    if (
      getMatch &&
      request.method === 'PUT'
    ) {
      const key =
        decodeURIComponent(
          getMatch[1]
        );

      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'ADMIN',
            'BOOTSTRAP'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      const role =
        gate.session.role;

      /*
       * Master-Konto ist unveränderlich.
       */
      if (
        key ===
        'gg_master_account'
      ) {
        const existingMaster =
          await env.DB
            .prepare(
              'SELECT key FROM app_state WHERE key = ?'
            )
            .bind(
              'gg_master_account'
            )
            .first();

        if (existingMaster) {
          return json(
            {
              ok: false,
              error:
                'master_immutable'
            },
            403
          );
        }

        if (
          role !== 'BOOTSTRAP' &&
          role !== 'MASTER'
        ) {
          return json(
            {
              ok: false,
              error: 'forbidden'
            },
            403
          );
        }
      }

      /*
       * Nur Master/Bootstrap dürfen Admin-Konfiguration
       * und Initialisierungsstatus ändern.
       */
      else if (
        key === 'vereinAdmins' ||
        key ===
          'adminSystemInitialisiert'
      ) {
        if (
          role !== 'MASTER' &&
          role !== 'BOOTSTRAP'
        ) {
          return json(
            {
              ok: false,
              error: 'forbidden'
            },
            403
          );
        }
      }

      /*
       * Bootstrap darf keine normalen sensitiven
       * Datenbereiche überschreiben.
       */
      else if (
        SENSITIVE_KEYS.has(key) &&
        role === 'BOOTSTRAP'
      ) {
        return json(
          {
            ok: false,
            error: 'forbidden'
          },
          403
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            ok: false,
            error:
              'Invalid JSON body'
          },
          400
        );
      }

      if (
        typeof body?.value !==
        'string'
      ) {
        return json(
          {
            ok: false,
            error:
              'Body must contain string field "value"'
          },
          400
        );
      }

      /*
       * Master darf niemals geleert werden.
       */
      if (
        key ===
          'gg_master_account' &&
        body.value.trim() === ''
      ) {
        return json(
          {
            ok: false,
            error:
              'master_cannot_be_cleared'
          },
          403
        );
      }

      const existing =
        await env.DB
          .prepare(
            'SELECT value, updated_at FROM app_state WHERE key = ?'
          )
          .bind(key)
          .first();

      const now =
        new Date().toISOString();

      const clientTs =
        typeof body.clientUpdatedAt ===
        'string'
          ? body.clientUpdatedAt
          : null;

      const clientMs =
        clientTs
          ? Date.parse(clientTs)
          : NaN;

      /*
       * Neuer Key.
       */
      if (!existing) {
        const ts =
          Number.isFinite(clientMs)
            ? new Date(
                clientMs
              ).toISOString()
            : now;

        await env.DB
          .prepare(`
            INSERT INTO app_state
            (
              key,
              value,
              updated_at
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            key,
            body.value,
            ts
          )
          .run();

        return json({
          ok: true,
          key,
          updated_at: ts,
          created: true
        });
      }

      /*
       * Master bleibt unveränderlich.
       */
      if (
        key ===
        'gg_master_account'
      ) {
        return json(
          {
            ok: false,
            error:
              'master_immutable'
          },
          403
        );
      }

      const existingMs =
        existing.updated_at
          ? Date.parse(
              existing.updated_at
            )
          : NaN;

      /*
       * Bei unklarer Zeit niemals einen
       * möglicherweise neueren D1-Stand überschreiben.
       */
      if (
        !Number.isFinite(
          clientMs
        ) ||
        !Number.isFinite(
          existingMs
        )
      ) {
        return json({
          ok: true,
          key,
          updated_at:
            existing.updated_at,
          skipped: true,
          reason:
            'timestamp_unclear_keep_existing'
        });
      }

      /*
       * Älteren Clientstand niemals über
       * den neueren D1-Stand schreiben.
       */
      if (
        clientMs <
        existingMs
      ) {
        return json({
          ok: true,
          key,
          updated_at:
            existing.updated_at,
          skipped: true,
          reason:
            'client_older_than_d1'
        });
      }

      const ts =
        new Date(
          clientMs
        ).toISOString();

      await env.DB
        .prepare(`
          UPDATE app_state
          SET
            value = ?,
            updated_at = ?
          WHERE key = ?
        `)
        .bind(
          body.value,
          ts,
          key
        )
        .run();

      return json({
        ok: true,
        key,
        updated_at: ts,
        updated: true
      });
    }

    /*
     * =========================================================
     * MIGRATION
     * =========================================================
     */

    if (
      path === '/api/migrate' &&
      request.method === 'POST'
    ) {
      const gate =
        await requireSession(
          request,
          env,
          [
            'MASTER',
            'BOOTSTRAP'
          ]
        );

      if (!gate.ok) {
        return json(
          {
            ok: false,
            error: gate.error
          },
          gate.status
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            ok: false,
            error:
              'Invalid JSON body'
          },
          400
        );
      }

      const items =
        body?.items;

      if (
        !items ||
        typeof items !==
          'object'
      ) {
        return json(
          {
            ok: false,
            error:
              'Body must contain object "items"'
          },
          400
        );
      }

      const now =
        new Date().toISOString();

      let written = 0;
      let skipped = 0;

      const keys =
        Object.keys(items);

      for (const key of keys) {
        /*
         * Bestehenden Master niemals
         * durch Migration überschreiben.
         */
        if (
          key ===
          'gg_master_account'
        ) {
          const existsMaster =
            await env.DB
              .prepare(
                'SELECT key FROM app_state WHERE key = ?'
              )
              .bind(key)
              .first();

          if (existsMaster) {
            skipped++;
            continue;
          }
        }

        const raw =
          items[key];

        let value = null;
        let clientTs = null;

        if (
          typeof raw ===
          'string'
        ) {
          value = raw;
        } else if (
          raw &&
          typeof raw ===
            'object' &&
          typeof raw.value ===
            'string'
        ) {
          value =
            raw.value;

          if (
            typeof raw.clientUpdatedAt ===
            'string'
          ) {
            clientTs =
              raw.clientUpdatedAt;
          }
        } else {
          continue;
        }

        const existing =
          await env.DB
            .prepare(
              'SELECT key FROM app_state WHERE key = ?'
            )
            .bind(key)
            .first();

        /*
         * Migration ist ausschließlich
         * für noch nicht vorhandene Keys.
         */
        if (existing) {
          skipped++;
          continue;
        }

        const clientMs =
          clientTs
            ? Date.parse(clientTs)
            : NaN;

        const ts =
          Number.isFinite(clientMs)
            ? new Date(
                clientMs
              ).toISOString()
            : now;

        await env.DB
          .prepare(`
            INSERT INTO app_state
            (
              key,
              value,
              updated_at
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            key,
            value,
            ts
          )
          .run();

        written++;
      }

      return json({
        ok: true,
        written,
        skipped,
        keys:
          keys.length,
        updated_at:
          now
      });
    }

    return json(
      {
        ok: false,
        error: 'Not found'
      },
      404
    );

  } catch (e) {
    console.error(
      '[GG-D1]',
      e
    );

    return json(
      {
        ok: false,
        error:
          String(
            e?.message ||
            e
          )
      },
      500
    );
  }
}

export default {
  async fetch(
    request,
    env
  ) {
    /*
     * CORS Preflight
     */
    if (
      request.method ===
      'OPTIONS'
    ) {
      return new Response(
        null,
        {
          status: 204,
          headers:
            CORS_HEADERS
        }
      );
    }

    const url =
      new URL(request.url);

    /*
     * API-Anfragen gehen
     * ausschließlich an diesen Worker.
     */
    if (
      url.pathname.startsWith(
        '/api/'
      )
    ) {
      return handleApi(
        request,
        env
      );
    }

    /*
     * Alle anderen Anfragen
     * gehen an Cloudflare Assets.
     */
    if (env.ASSETS) {
      return env.ASSETS.fetch(
        request
      );
    }

    return new Response(
      'ASSETS binding missing – index.html not available',
      {
        status: 500
      }
    );
  },
};
