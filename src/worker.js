// SUNLIGHT API — Cloudflare Worker + D1 (binding name: DB). No secrets or env vars required.
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization', 'access-control-allow-methods': 'GET, POST, OPTIONS' };
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const PAGE = null; /*__PAGE__*/
const ONLINE_MS = 30000, SESSION_MS = 30 * 864e5;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const likeEsc = s => s.replace(/[\\%_]/g, '\\$&');            // escape LIKE wildcards in user input
const MEDIA_KEY = /^u\d+\/[a-f0-9]{32}$/;                  // keys we generate: u<userId>/<random>
const MEDIA_RULES = { image: { max: 1000000 }, voice: { max: 1000000 } };   // max raw bytes per file; files are stored in D1, so they are kept small
const CHUNK = 180000;                                      // base64 characters per D1 row (many small rows, never one huge value)
const B64 = /^[A-Za-z0-9+\/]+={0,2}$/;
function sniff(kind, b64) {                                // what the file REALLY is (first bytes), never what the client claims
  const h = [...atob(b64.slice(0, 24))].map(c => c.charCodeAt(0)), at = (i, str) => [...str].every((c, j) => h[i + j] === c.charCodeAt(0));
  if (kind === 'image') {
    if (h[0] === 0xFF && h[1] === 0xD8 && h[2] === 0xFF) return 'image/jpeg';
    if (h[0] === 0x89 && at(1, 'PNG')) return 'image/png';
    if (at(0, 'GIF8')) return 'image/gif';
    if (at(0, 'RIFF') && at(8, 'WEBP')) return 'image/webp';
  } else {
    if (h[0] === 0x1A && h[1] === 0x45 && h[2] === 0xDF && h[3] === 0xA3) return 'audio/webm';
    if (at(0, 'OggS')) return 'audio/ogg';
    if (at(4, 'ftyp')) return 'audio/mp4';
    if (at(0, 'ID3') || (h[0] === 0xFF && (h[1] & 0xE6) === 0xE2)) return 'audio/mpeg';
    if (at(0, 'RIFF') && at(8, 'WAVE')) return 'audio/wav';
  }
  return null;
}
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
  `CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id)`,
  `CREATE TABLE IF NOT EXISTS media (key TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, type TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS media_chunks (key TEXT NOT NULL, idx INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (key, idx))`
];
const USER_COLS = { username: "TEXT", email: 'TEXT', name: "TEXT NOT NULL DEFAULT ''", pass_hash: "TEXT NOT NULL DEFAULT ''", salt: "TEXT NOT NULL DEFAULT ''", created_at: 'INTEGER NOT NULL DEFAULT 0', last_seen: 'INTEGER NOT NULL DEFAULT 0' };
const MSG_COLS = { type: "TEXT NOT NULL DEFAULT 'text'", media_key: 'TEXT', media_type: 'TEXT', media_size: 'INTEGER', duration: 'INTEGER', reply_to: 'INTEGER', delivered_at: 'INTEGER', deleted_at: 'INTEGER' };
let ready = null;
function ensureSchema(db) {
  ready ??= (async () => {
    for (const q of TABLES) await db.prepare(q).run();
    const have = (await db.prepare('PRAGMA table_info(users)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(USER_COLS)) if (!have.includes(col)) await db.prepare(`ALTER TABLE users ADD COLUMN ${col} ${type}`).run();
    await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL').run();
    const haveM = (await db.prepare('PRAGMA table_info(messages)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(MSG_COLS)) if (!haveM.includes(col)) await db.prepare(`ALTER TABLE messages ADD COLUMN ${col} ${type}`).run();
    await db.prepare('CREATE INDEX IF NOT EXISTS idx_msg_media ON messages(media_key)').run();
    await db.prepare('CREATE INDEX IF NOT EXISTS idx_msg_deliv ON messages(receiver_id, delivered_at)').run();
  })().catch(e => { ready = null; throw e; });
  return ready;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      // Page: prefer the static-assets binding (wrangler deploy); otherwise serve the page embedded in this file
      // (build.py fills PAGE), so a single worker.js pasted into the Cloudflare dashboard works with no extra binding.
      if (env.ASSETS) return env.ASSETS.fetch(req);
      if (PAGE && (req.method === 'GET' || req.method === 'HEAD'))
        return new Response(req.method === 'HEAD' ? null : PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } });
      return new Response('SUNLIGHT: no page is available. Use worker.single.js (page embedded), or deploy with wrangler so the "ASSETS" binding exists.', { status: 500, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
    }
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
  if (post && Number(req.headers.get('content-length') || 0) > 1700000) return json({ error: 'File is too large' }, 413);
  const body = post ? await req.json().catch(() => ({})) : {};

  if (p === 'health') {
    const r = await db.prepare('SELECT COUNT(*) n FROM users').first();
    return json({ ok: true, database: 'connected', assets: !!env.ASSETS, users: r.n });
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
  const me = tok ? await db.prepare('SELECT u.id,u.username,u.name,u.last_seen FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at>?').bind(tok, now - SESSION_MS).first() : null;
  if (!me) return json({ error: 'Please log in' }, 401);
  if (now - me.last_seen > 10000) await db.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now, me.id).run(); // throttled: saves D1 writes
  delete me.last_seen;

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
    await db.prepare('UPDATE messages SET delivered_at=? WHERE receiver_id=? AND delivered_at IS NULL').bind(now, me.id).run();
    const { results } = await db.prepare(`
      SELECT u.id,u.name,u.last_seen,m.body last_body,m.type last_type,m.created_at last_at,m.sender_id last_sender,m.read_at last_read,m.delivered_at last_delivered,
        m.deleted_at last_deleted,
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
    await db.prepare('UPDATE messages SET read_at=?1, delivered_at=COALESCE(delivered_at,?1) WHERE sender_id=?2 AND receiver_id=?3 AND read_at IS NULL').bind(now, peerId, me.id).run();
    const { results } = await db.prepare(`
      SELECT id,sender_id,body,type,media_key,media_type,media_size,duration,reply_to,created_at,delivered_at,read_at,deleted_at FROM (
        SELECT * FROM messages WHERE (sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1) ORDER BY id DESC LIMIT 200
      ) ORDER BY id`).bind(me.id, peerId).all();
    return json({ messages: results, online: now - peer.last_seen < ONLINE_MS, last_seen: peer.last_seen });
  }

  if (p === 'messages' && post) {
    const to = Number(body.to), text = String(body.body || '').trim();
    const type = ['text', 'image', 'voice'].includes(body.type) ? body.type : 'text';
    if (text.length > 2000 || (type === 'text' && !text)) return json({ error: 'Message must be 1–2000 characters' }, 400);
    if (!Number.isInteger(to) || to === me.id || !(await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())) return json({ error: 'User not found' }, 404);
    let key = null, mtype = null, msize = null, dur = null, replyTo = null;
    if (type !== 'text') {
      key = String(body.media_key || '');
      if (!MEDIA_KEY.test(key) || !key.startsWith('u' + me.id + '/')) return json({ error: 'Invalid media' }, 400);   // only your own uploads
      const up = await db.prepare('SELECT type,size FROM media WHERE key=? AND owner_id=?').bind(key, me.id).first();
      if (!up) return json({ error: 'Upload not found. Please try again.' }, 400);
      mtype = up.type;
      if (!mtype.startsWith(type === 'image' ? 'image/' : 'audio/')) return json({ error: 'Media type does not match' }, 400);
      if (await db.prepare('SELECT id FROM messages WHERE media_key=?').bind(key).first()) return json({ error: 'Media already used' }, 409);
      msize = up.size; dur = type === 'voice' ? Math.min(3600, Math.max(0, Math.round(Number(body.duration) || 0))) : null;
    }
    if (body.reply_to != null) {
      const rid = Number(body.reply_to);
      if (Number.isInteger(rid) && await db.prepare('SELECT id FROM messages WHERE id=?1 AND ((sender_id=?2 AND receiver_id=?3) OR (sender_id=?3 AND receiver_id=?2))').bind(rid, me.id, to).first()) replyTo = rid;
    }
    const r = await db.prepare('INSERT INTO messages(sender_id,receiver_id,body,created_at,type,media_key,media_type,media_size,duration,reply_to) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .bind(me.id, to, text, now, type, key, mtype, msize, dur, replyTo).run();
    return json({ id: r.meta.last_row_id, created_at: now });
  }

  // delete my own message for everyone (media is removed from storage too)
  if (p === 'messages/delete' && post) {
    const id = Number(body.id);
    const m = Number.isInteger(id) ? await db.prepare('SELECT id,media_key FROM messages WHERE id=? AND sender_id=? AND deleted_at IS NULL').bind(id, me.id).first() : null;
    if (!m) return json({ error: 'Message not found' }, 404);
    await db.prepare("UPDATE messages SET deleted_at=?, body='', media_key=NULL WHERE id=?").bind(now, id).run();
    if (m.media_key) await db.batch([db.prepare('DELETE FROM media_chunks WHERE key=?').bind(m.media_key), db.prepare('DELETE FROM media WHERE key=?').bind(m.media_key)]);
    return json({ ok: true });
  }

  // ---- media (photos, voice notes) stored in D1: JSON upload {kind, data: base64}, authenticated download ----
  if (p === 'media' && post) {
    const kind = String(body.kind || ''), rule = MEDIA_RULES[kind], data = typeof body.data === 'string' ? body.data : '';
    if (!rule) return json({ error: 'Unknown media kind' }, 400);
    if (data.length < 24 || data.length % 4 !== 0 || !B64.test(data.slice(0, 64)) || !B64.test(data.slice(-64))) return json({ error: 'Invalid file' }, 400);
    const size = data.length / 4 * 3 - (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
    if (size > rule.max) return json({ error: kind === 'voice' ? 'Voice note is too long' : 'File is too large' }, 413);
    const type = sniff(kind, data);
    if (!type) return json({ error: 'This file type is not allowed' }, 415);
    const old = now - 3600000;                              // tidy up this user's uploads that were never sent in a message
    await db.batch([
      db.prepare('DELETE FROM media_chunks WHERE key IN (SELECT key FROM media WHERE owner_id=? AND created_at<? AND key NOT IN (SELECT media_key FROM messages WHERE media_key IS NOT NULL))').bind(me.id, old),
      db.prepare('DELETE FROM media WHERE owner_id=? AND created_at<? AND key NOT IN (SELECT media_key FROM messages WHERE media_key IS NOT NULL)').bind(me.id, old)
    ]);
    const key = `u${me.id}/${rand(16)}`, stmts = [db.prepare('INSERT INTO media(key,owner_id,type,size,created_at) VALUES(?,?,?,?,?)').bind(key, me.id, type, size, now)];
    for (let i = 0, n = 0; i < data.length; i += CHUNK, n++) stmts.push(db.prepare('INSERT INTO media_chunks(key,idx,data) VALUES(?,?,?)').bind(key, n, data.slice(i, i + CHUNK)));
    await db.batch(stmts);
    return json({ key, size, type });
  }

  if (p.startsWith('media/') && !post) {
    const key = p.slice(6);
    if (!MEDIA_KEY.test(key)) return json({ error: 'Not found' }, 404);
    const allowed = key.startsWith('u' + me.id + '/') ||
      await db.prepare('SELECT 1 ok FROM messages WHERE media_key=? AND deleted_at IS NULL AND (sender_id=? OR receiver_id=?)').bind(key, me.id, me.id).first();
    const m = allowed ? await db.prepare('SELECT type FROM media WHERE key=?').bind(key).first() : null;
    if (!m) return json({ error: 'Not found' }, 404);
    const { results } = await db.prepare('SELECT data FROM media_chunks WHERE key=? ORDER BY idx').bind(key).all();
    return json({ type: m.type, data: results.map(r => r.data).join('') });
  }

  return json({ error: 'Not found' }, 404);
}
