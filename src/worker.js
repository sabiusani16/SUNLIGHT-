// SUNLIGHT API — Cloudflare Worker + D1 (binding name: DB). No secrets or env vars required.
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization', 'access-control-allow-methods': 'GET, POST, OPTIONS' };
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const ONLINE_MS = 30000, SESSION_MS = 30 * 864e5;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const likeEsc = s => s.replace(/[\\%_]/g, '\\$&');            // escape LIKE wildcards in user input
const publicUser = (u, now) => ({ id: u.id, name: u.name, username: u.username, online: now - u.last_seen < ONLINE_MS }); // never includes email / hashes

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}
const safeEq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

/* ---- schema: created / repaired automatically, so a missing table can never cause a 500 ---- */
const TABLES = [
  `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, email TEXT, name TEXT NOT NULL, pass_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, receiver_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, read_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id, receiver_id, id)`,
  `CREATE INDEX IF NOT EXISTS idx_msg_recv ON messages(receiver_id, read_at)`,
  `CREATE TABLE IF NOT EXISTS contacts (owner_id INTEGER NOT NULL, contact_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner_id, contact_id))`,
  `CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id)`
];
const USER_COLS = { username: "TEXT", email: 'TEXT', name: "TEXT NOT NULL DEFAULT ''", pass_hash: "TEXT NOT NULL DEFAULT ''", salt: "TEXT NOT NULL DEFAULT ''", created_at: 'INTEGER NOT NULL DEFAULT 0', last_seen: 'INTEGER NOT NULL DEFAULT 0' };
let ready = null;
function ensureSchema(db) {
  ready ??= (async () => {
    for (const q of TABLES) await db.prepare(q).run();
    const have = (await db.prepare('PRAGMA table_info(users)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(USER_COLS)) if (!have.includes(col)) await db.prepare(`ALTER TABLE users ADD COLUMN ${col} ${type}`).run();
    await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL').run();
  })().catch(e => { ready = null; throw e; });
  return ready;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (!env.DB) return json({ error: 'Database is not connected. Add the D1 binding named "DB" in wrangler.toml and redeploy.', code: 'DB_BINDING' }, 500);
    try {
      await ensureSchema(env.DB);
      return await route(req, env, url);
    } catch (e) {
      const msg = String(e && e.message || e), ref = rand(3);
      console.error(`[SUNLIGHT ${ref}]`, msg);
      if (/no such table|no such column/i.test(msg)) return json({ error: 'Database tables are missing. Run: wrangler d1 execute DB --remote --file=schema.sql', code: 'DB_SCHEMA' }, 500);
      return json({ error: `Server error (ref ${ref}). Please try again.`, code: 'SERVER' }, 500);
    }
  }
};

async function startSession(db, user, now) {
  const token = rand(32);
  await db.prepare('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)').bind(token, user.id, now).run();
  return json({ token, user });
}

async function route(req, env, url) {
  const db = env.DB, p = url.pathname.slice(5), now = Date.now();
  const post = req.method === 'POST';
  const body = post ? await req.json().catch(() => ({})) : {};

  if (p === 'health') {
    const r = await db.prepare('SELECT COUNT(*) n FROM users').first();
    return json({ ok: true, database: 'connected', users: r.n });
  }

  if (p === 'register' && post) {
    const username = String(body.username || '').trim().toLowerCase();
    const email = String(body.email || '').trim().toLowerCase();
    const name = String(body.name || '').trim();
    const pw = String(body.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return json({ error: 'Username: 3–20 letters, numbers or _' }, 400);
    if (email && !EMAIL.test(email)) return json({ error: 'Enter a valid email address' }, 400);
    if (!name || name.length > 40) return json({ error: 'Enter your name (max 40 characters)' }, 400);
    if (pw.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);
    const salt = rand(16);
    let r;
    try {
      r = await db.prepare('INSERT INTO users(username,email,name,pass_hash,salt,created_at,last_seen) VALUES(?,?,?,?,?,?,?)')
        .bind(username, email || null, name, await hashPw(pw, salt), salt, now, now).run();
    } catch (e) {
      if (/UNIQUE|constraint/i.test(String(e && e.message))) return json({ error: 'Username or email already taken' }, 409);
      throw e;
    }
    return startSession(db, { id: r.meta.last_row_id, username, name }, now);
  }

  if (p === 'login' && post) {
    const ident = String(body.username || body.email || body.identifier || '').trim().toLowerCase();
    const pw = String(body.password || '');
    if (!ident || !pw) return json({ error: 'Enter your username (or email) and password' }, 400);
    const u = await db.prepare('SELECT id,username,name,pass_hash,salt FROM users WHERE username=?1 OR email=?1').bind(ident).first();
    // same work + same message whether the account exists or not
    const ok = u && u.pass_hash && safeEq(await hashPw(pw, u.salt), u.pass_hash);
    if (!ok) return json({ error: 'Incorrect username/email or password' }, 401);
    return startSession(db, { id: u.id, username: u.username, name: u.name }, now);
  }

  // ---- authenticated routes ----
  const tok = (req.headers.get('authorization') || '').replace('Bearer ', '');
  const me = tok ? await db.prepare('SELECT u.id,u.username,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at>?').bind(tok, now - SESSION_MS).first() : null;
  if (!me) return json({ error: 'Please log in' }, 401);
  await db.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now, me.id).run();

  if (p === 'me') return json({ user: me });

  if (p === 'logout' && post) {
    await db.prepare('DELETE FROM sessions WHERE token=?').bind(tok).run();
    return json({ ok: true });
  }

  // ---- search registered users by username or full name (authenticated only) ----
  if (p === 'users/search' && !post) {
    const q = (url.searchParams.get('q') || '').trim().replace(/^@+/, '').slice(0, 40);
    if (!q) return json({ users: [] });
    const ql = q.toLowerCase();
    const { results } = await db.prepare(`
      SELECT u.id,u.name,u.username,u.last_seen,
        EXISTS(SELECT 1 FROM contacts c WHERE c.owner_id=?1 AND c.contact_id=u.id) is_contact
      FROM users u
      WHERE u.id!=?1 AND (u.username LIKE ?2 ESCAPE '\\' OR u.name LIKE ?2 ESCAPE '\\')
      ORDER BY CASE WHEN u.username=?3 THEN 0 WHEN u.username LIKE ?4 ESCAPE '\\' THEN 1 WHEN u.name LIKE ?4 ESCAPE '\\' THEN 2 ELSE 3 END, u.name
      LIMIT 30`).bind(me.id, '%' + likeEsc(q) + '%', ql, likeEsc(q) + '%').all();
    return json({ users: results.map(u => ({ ...publicUser(u, now), is_contact: !!u.is_contact })) });
  }

  // ---- my saved contacts ----
  if (p === 'contacts' && !post) {
    const { results } = await db.prepare(
      'SELECT u.id,u.name,u.username,u.last_seen FROM contacts c JOIN users u ON u.id=c.contact_id WHERE c.owner_id=? ORDER BY u.name LIMIT 500'
    ).bind(me.id).all();
    return json({ contacts: results.map(u => publicUser(u, now)) });
  }

  if (p === 'contacts' && post) {
    const id = Number(body.user_id);
    if (!Number.isInteger(id) || id < 1) return json({ error: 'Invalid user' }, 400);
    if (id === me.id) return json({ error: 'You cannot add yourself as a contact' }, 400);
    const u = await db.prepare('SELECT id,name,username,last_seen FROM users WHERE id=?').bind(id).first();
    if (!u) return json({ error: 'User not found' }, 404);
    const r = await db.prepare('INSERT OR IGNORE INTO contacts(owner_id,contact_id,created_at) VALUES(?,?,?)').bind(me.id, id, now).run();
    return json({ contact: publicUser(u, now), already: !r.meta.changes });
  }

  if (p === 'contacts/remove' && post) {
    const id = Number(body.user_id);
    if (!Number.isInteger(id) || id < 1) return json({ error: 'Invalid user' }, 400);
    await db.prepare('DELETE FROM contacts WHERE owner_id=? AND contact_id=?').bind(me.id, id).run();
    return json({ ok: true });
  }

  if (p === 'chats') {
    const { results } = await db.prepare(`
      SELECT u.id,u.name,u.last_seen,m.body last_body,m.created_at last_at,m.sender_id last_sender,m.read_at last_read,
        (SELECT COUNT(*) FROM messages x WHERE x.sender_id=u.id AND x.receiver_id=?1 AND x.read_at IS NULL) unread
      FROM users u JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE (sender_id=?1 AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=?1))
      WHERE u.id!=?1 ORDER BY m.id DESC LIMIT 200`).bind(me.id).all();
    return json({ chats: results.map(c => ({ ...c, online: now - c.last_seen < ONLINE_MS, last_seen: undefined })) });
  }

  if (p === 'messages' && !post) {
    const peerId = parseInt(url.searchParams.get('with'), 10);
    if (!Number.isInteger(peerId)) return json({ error: 'User not found' }, 404);
    const peer = await db.prepare('SELECT id,last_seen FROM users WHERE id=?').bind(peerId).first();
    if (!peer) return json({ error: 'User not found' }, 404);
    await db.prepare('UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL').bind(now, peerId, me.id).run();
    const { results } = await db.prepare(`
      SELECT id,sender_id,body,created_at,read_at FROM (
        SELECT * FROM messages WHERE (sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1) ORDER BY id DESC LIMIT 200
      ) ORDER BY id`).bind(me.id, peerId).all();
    return json({ messages: results, online: now - peer.last_seen < ONLINE_MS });
  }

  if (p === 'messages' && post) {
    const to = parseInt(body.to, 10), text = String(body.body || '').trim();
    if (!text || text.length > 2000) return json({ error: 'Message must be 1–2000 characters' }, 400);
    if (!Number.isInteger(to) || to === me.id || !(await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())) return json({ error: 'User not found' }, 404);
    const r = await db.prepare('INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)').bind(me.id, to, text, now).run();
    return json({ id: r.meta.last_row_id });
  }

  return json({ error: 'Not found' }, 404);
}
