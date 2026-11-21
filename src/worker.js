// SUNLIGHT API — Cloudflare Worker + D1 (binding name: DB). No secrets or env vars required.
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type, authorization', 'access-control-allow-methods': 'GET, POST, OPTIONS' };
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const REPORT_REASONS = ['spam', 'harassment', 'inappropriate', 'scam', 'threats', 'other'];
const THEME_BG = ['midnight', 'forest', 'gold', 'ocean', 'rose', 'slate', 'dots'], THEME_COLOR = ['gold', 'blue', 'purple', 'rose', 'teal'];   // allowed chat themes (anything else is rejected)
const PAGE = null; /*__PAGE__*/
const RING_MS = 45000, BEAT_MS = 25000, STUN = [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }];
const ONLINE_MS = 30000, SESSION_MS = 30 * 864e5;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const likeEsc = s => s.replace(/[\\%_]/g, '\\$&');            // escape LIKE wildcards in user input
const MEDIA_KEY = /^u\d+\/[a-f0-9]{32}$/;                  // keys we generate: u<userId>/<random>
const MEDIA_RULES = { image: { max: 1000000 }, voice: { max: 1000000 } };   // max raw bytes per file; files are stored in D1, so they are kept small
const VIDEO_MAX = 20 * 1024 * 1024;                         // 20 MB per video (R2 free tier is 10 GB)
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
const publicUser = (u, now) => ({ id: u.id, name: u.name, username: u.username, avatar: u.avatar_key || null, online: now - u.last_seen < ONLINE_MS }); // never includes email / hashes

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
  `CREATE TABLE IF NOT EXISTS media_chunks (key TEXT NOT NULL, idx INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (key, idx))`,
  `CREATE TABLE IF NOT EXISTS statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, body TEXT, caption TEXT, bg INTEGER, media_key TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS chat_prefs (user_id INTEGER NOT NULL, peer_id INTEGER NOT NULL, theme TEXT, cleared_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, peer_id))`,
  `CREATE TABLE IF NOT EXISTS blocks (blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (blocker_id, blocked_id))`,
  `CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id)`,
  `CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, reported_id INTEGER NOT NULL, message_id INTEGER, message_text TEXT, reason TEXT NOT NULL, details TEXT, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_reports_reported ON reports(reported_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS status_likes (status_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (status_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, actor_id INTEGER NOT NULL, status_id INTEGER, created_at INTEGER NOT NULL, read_at INTEGER, UNIQUE (user_id, type, actor_id, status_id))`,
  `CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, id)`,
  `CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'ringing', created_at INTEGER NOT NULL, ringing_at INTEGER, answered_at INTEGER, ended_at INTEGER, end_reason TEXT, duration INTEGER NOT NULL DEFAULT 0, caller_beat INTEGER NOT NULL DEFAULT 0, callee_beat INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id, id)`,
  `CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id, id)`,
  `CREATE TABLE IF NOT EXISTS call_signals (id INTEGER PRIMARY KEY AUTOINCREMENT, call_id INTEGER NOT NULL, to_user INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_signals_to ON call_signals(to_user, call_id, id)`,
  `CREATE INDEX IF NOT EXISTS idx_status_user ON statuses(user_id, expires_at)`,
  `CREATE INDEX IF NOT EXISTS idx_status_media ON statuses(media_key)`,
  `CREATE TABLE IF NOT EXISTS status_views (status_id INTEGER NOT NULL, viewer_id INTEGER NOT NULL, viewed_at INTEGER NOT NULL, PRIMARY KEY (status_id, viewer_id))`
];
const USER_COLS = { username: "TEXT", email: 'TEXT', name: "TEXT NOT NULL DEFAULT ''", pass_hash: "TEXT NOT NULL DEFAULT ''", salt: "TEXT NOT NULL DEFAULT ''", created_at: 'INTEGER NOT NULL DEFAULT 0', last_seen: 'INTEGER NOT NULL DEFAULT 0', avatar_key: 'TEXT' };
const MSG_COLS = { type: "TEXT NOT NULL DEFAULT 'text'", media_key: 'TEXT', media_type: 'TEXT', media_size: 'INTEGER', duration: 'INTEGER', reply_to: 'INTEGER', delivered_at: 'INTEGER', deleted_at: 'INTEGER', status_id: 'INTEGER', status_snap: 'TEXT' };
let ready = null;
// Two requests can start the schema check at the same moment (e.g. right after a deploy); the loser must not fail with "duplicate column".
const addCol = async (db, t, c, ty) => { try { await db.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${ty}`).run(); } catch (e) { if (!/duplicate column/i.test(String(e && e.message || e))) throw e; } };
function ensureSchema(db) {
  ready ??= (async () => {
    for (const q of TABLES) await db.prepare(q).run();
    const have = (await db.prepare('PRAGMA table_info(users)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(USER_COLS)) if (!have.includes(col)) await addCol(db, 'users', col, type);
    await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL').run();
    const haveM = (await db.prepare('PRAGMA table_info(messages)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(MSG_COLS)) if (!haveM.includes(col)) await addCol(db, 'messages', col, type);
    const haveC = (await db.prepare('PRAGMA table_info(calls)').all()).results.map(c => c.name);
    if (!haveC.includes('video')) await addCol(db, 'calls', 'video', 'INTEGER NOT NULL DEFAULT 0');
    const haveP = (await db.prepare('PRAGMA table_info(chat_prefs)').all()).results.map(c => c.name);
    if (!haveP.includes('cleared_at')) await addCol(db, 'chat_prefs', 'cleared_at', 'INTEGER NOT NULL DEFAULT 0');
    await db.prepare('CREATE INDEX IF NOT EXISTS idx_calls_pair ON calls(caller_id, callee_id)').run();
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
  const rawVideo = post && p === 'video';                    // videos are sent as raw bytes (not JSON) and live in R2
  if (post && !rawVideo && Number(req.headers.get('content-length') || 0) > 1700000) return json({ error: 'File is too large' }, 413);
  const body = post && !rawVideo ? await req.json().catch(() => ({})) : {};

  const visibleStatus = id => db.prepare('SELECT * FROM statuses s WHERE s.id=?1 AND s.expires_at>?2 AND (s.user_id=?3 OR (EXISTS(SELECT 1 FROM contacts c WHERE c.owner_id=s.user_id AND c.contact_id=?3) AND EXISTS(SELECT 1 FROM contacts c2 WHERE c2.owner_id=?3 AND c2.contact_id=s.user_id) AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=s.user_id AND b.blocked_id=?3) OR (b.blocker_id=?3 AND b.blocked_id=s.user_id))))').bind(id, now, me.id).first();
  const dropAny = async key => {                             // delete an upload everywhere: D1 chunks, the media row and (videos) the R2 object
    const m = await db.prepare('SELECT type FROM media WHERE key=?').bind(key).first();
    if (m && m.type.startsWith('video/') && env.MEDIA) await env.MEDIA.delete(key).catch(() => {});
    await db.batch([db.prepare('DELETE FROM media_chunks WHERE key=?').bind(key), db.prepare('DELETE FROM media WHERE key=?').bind(key)]);
  };

  if (p === 'health') {
    const r = await db.prepare('SELECT COUNT(*) n FROM users').first();
    return json({ ok: true, database: 'connected', video: !!env.MEDIA, assets: !!env.ASSETS, users: r.n });
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
    return startSession(db, { id: r.meta.last_row_id, username, name, avatar: null }, now);
  }

  if (p === 'login' && post) {
    const ident = String(body.username || body.email || body.identifier || '').trim().toLowerCase();
    const pw = String(body.password || '');
    if (!ident || !pw) return json({ error: 'Enter your username (or email) and password' }, 400);
    const u = await db.prepare('SELECT id,username,name,avatar_key,pass_hash,salt FROM users WHERE username=?1 OR email=?1').bind(ident).first();
    // same work + same message whether the account exists or not
    const ok = u && u.pass_hash && safeEq(await hashPw(pw, u.salt), u.pass_hash);
    if (!ok) return json({ error: 'Incorrect username/email or password' }, 401);
    return startSession(db, { id: u.id, username: u.username, name: u.name, avatar: u.avatar_key || null }, now);
  }

  // ---- authenticated routes ----
  const tok = (req.headers.get('authorization') || '').replace('Bearer ', '');
  const me = tok ? await db.prepare('SELECT u.id,u.username,u.name,u.avatar_key avatar,u.last_seen FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at>?').bind(tok, now - SESSION_MS).first() : null;
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
      SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,
        EXISTS(SELECT 1 FROM contacts c WHERE c.owner_id=?1 AND c.contact_id=u.id) is_contact
      FROM users u
      WHERE u.id!=?1 AND (u.username LIKE ?2 ESCAPE '\\' OR u.name LIKE ?2 ESCAPE '\\')
      ORDER BY CASE WHEN u.username=?3 THEN 0 WHEN u.username LIKE ?4 ESCAPE '\\' THEN 1 WHEN u.name LIKE ?4 ESCAPE '\\' THEN 2 ELSE 3 END, u.name
      LIMIT 30`).bind(me.id, '%' + likeEsc(q) + '%', ql, likeEsc(q) + '%').all();
    return json({ users: results.map(u => ({ ...publicUser(u, now), is_contact: !!u.is_contact })) });
  }

  // ---- one user's public profile (only id, name, username, photo, online) ----
  const pm = p.match(/^users\/(\d{1,12})$/);
  if (pm && !post) {
    const u = await db.prepare(
      'SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,EXISTS(SELECT 1 FROM contacts c WHERE c.owner_id=?1 AND c.contact_id=u.id) is_contact FROM users u WHERE u.id=?2'
    ).bind(me.id, +pm[1]).first();
    if (!u) return json({ error: 'User not found' }, 404);
    return json({ user: { ...publicUser(u, now), is_contact: !!u.is_contact, is_me: u.id === me.id } });
  }

  // ---- my saved contacts ----
  if (p === 'contacts' && !post) {
    const { results } = await db.prepare(
      'SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen FROM contacts c JOIN users u ON u.id=c.contact_id WHERE c.owner_id=? ORDER BY u.name LIMIT 500'
    ).bind(me.id).all();
    return json({ contacts: results.map(u => publicUser(u, now)) });
  }

  if (p === 'contacts' && post) {
    const id = Number(body.user_id);
    if (!Number.isInteger(id) || id < 1) return json({ error: 'Invalid user' }, 400);
    if (id === me.id) return json({ error: 'You cannot add yourself as a contact' }, 400);
    const u = await db.prepare('SELECT id,name,username,avatar_key,last_seen FROM users WHERE id=?').bind(id).first();
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

  const iBlocked = (a, b) => db.prepare('SELECT 1 ok FROM blocks WHERE blocker_id=? AND blocked_id=?').bind(a, b).first();
  const eitherBlocked = (a, b) => db.prepare('SELECT 1 ok FROM blocks WHERE (blocker_id=?1 AND blocked_id=?2) OR (blocker_id=?2 AND blocked_id=?1)').bind(a, b).first();
  const peerOf = async raw => { const id = Number(raw); return Number.isInteger(id) && id !== me.id ? await db.prepare('SELECT id,name,username,avatar_key,last_seen FROM users WHERE id=?').bind(id).first() : null; };
  const clearedId = async peer => ((await db.prepare('SELECT cleared_id FROM chat_prefs WHERE user_id=? AND peer_id=?').bind(me.id, peer).first()) || {}).cleared_id || 0;

  // ---- chat options: theme / clear / export / block / report ----
  if (p === 'chat/theme' && post) {
    const peer = await peerOf(body.with); if (!peer) return json({ error: 'User not found' }, 404);
    let theme = null;
    if (body.theme != null) {                                 // validated against a fixed list: nothing else can be stored
      const bg = body.theme.bg == null ? null : String(body.theme.bg), c = body.theme.color == null ? null : String(body.theme.color);
      if ((bg !== null && !THEME_BG.includes(bg)) || (c !== null && !THEME_COLOR.includes(c))) return json({ error: 'Unknown theme' }, 400);
      theme = bg === null && c === null ? null : JSON.stringify({ bg, color: c });
    }
    await db.prepare('INSERT INTO chat_prefs(user_id,peer_id,theme) VALUES(?1,?2,?3) ON CONFLICT(user_id,peer_id) DO UPDATE SET theme=?3').bind(me.id, peer.id, theme).run();
    return json({ theme: theme ? JSON.parse(theme) : null });
  }
  if (p === 'chat/clear' && post) {                          // hides history for ME only: nothing is deleted, the other person keeps everything
    const peer = await peerOf(body.with); if (!peer) return json({ error: 'User not found' }, 404);
    const last = await db.prepare('SELECT MAX(id) m FROM messages WHERE (sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1)').bind(me.id, peer.id).first();
    await db.prepare('INSERT INTO chat_prefs(user_id,peer_id,cleared_id,cleared_at) VALUES(?1,?2,?3,?4) ON CONFLICT(user_id,peer_id) DO UPDATE SET cleared_id=?3,cleared_at=?4').bind(me.id, peer.id, (last && last.m) || 0, now).run();
    return json({ ok: true });
  }
  if (p === 'chat/export' && !post) {
    const peer = await peerOf(url.searchParams.get('with')); if (!peer) return json({ error: 'User not found' }, 404);
    const fmt = url.searchParams.get('format') === 'json' ? 'json' : 'txt';
    const from = await clearedId(peer.id);
    const { results } = await db.prepare('SELECT id,sender_id,body,type,media_key,media_type,media_size,duration,created_at,delivered_at,read_at,deleted_at,status_snap FROM messages WHERE ((sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1)) AND id>?3 ORDER BY id LIMIT 5000').bind(me.id, peer.id, from).all();   // only a conversation I am part of, only what I can still see
    const who = id => id === me.id ? { name: me.name, username: me.username } : { name: peer.name, username: peer.username };
    const rows = results.map(m => {
      const s = who(m.sender_id), media = m.media_key && !m.deleted_at ? { type: m.type, mime: m.media_type, size: m.media_size, duration: m.duration, reference: m.media_key } : null;
      let st = null; if (m.status_snap && !m.deleted_at) try { st = JSON.parse(m.status_snap); } catch {}
      return { id: m.id, time: new Date(m.created_at).toISOString(), from: s.name, username: s.username, type: m.deleted_at ? 'deleted' : m.type, text: m.deleted_at ? '' : m.body, media, status_reply_to: st ? { type: st.t, text: st.x } : null, delivered: !!m.delivered_at, read: !!m.read_at };
    });
    const stamp = new Date(now).toISOString().slice(0, 10), fname = `sunlight-chat-${peer.username || peer.id}-${stamp}.${fmt}`;
    let out, ct;
    if (fmt === 'json') { out = JSON.stringify({ exported_at: new Date(now).toISOString(), exported_by: { name: me.name, username: me.username }, conversation_with: { name: peer.name, username: peer.username }, messages: rows }, null, 2); ct = 'application/json; charset=utf-8'; }
    else {
      out = `SUNLIGHT chat with ${peer.name} (@${peer.username})\nExported ${new Date(now).toISOString()} by ${me.name} (@${me.username})\n${'-'.repeat(48)}\n` + rows.map(r => {
        const d = r.time.replace('T', ' ').slice(0, 19) + ' UTC', body = r.type === 'deleted' ? '[message deleted]' : r.type === 'text' ? r.text : `[${r.type}${r.media ? ' ' + r.media.reference : ''}]` + (r.text ? ' ' + r.text : '');
        return `[${d}] ${r.from}: ${r.status_reply_to ? `(reply to status: ${r.status_reply_to.text || r.status_reply_to.type}) ` : ''}${body}`;
      }).join('\n') + '\n';
      ct = 'text/plain; charset=utf-8';
    }
    return new Response(out, { headers: { 'content-type': ct, 'content-disposition': `attachment; filename="${fname}"`, 'cache-control': 'no-store', 'x-filename': fname, ...CORS } });
  }
  if (p === 'block' && post) {                                // blocking keeps all history; it only stops new messages / interactions
    const peer = await peerOf(body.user_id); if (!peer) return json({ error: 'User not found' }, 404);
    await db.prepare('INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at) VALUES(?,?,?)').bind(me.id, peer.id, now).run();
    return json({ ok: true, blocked: true });
  }
  if (p === 'unblock' && post) {
    const peer = await peerOf(body.user_id); if (!peer) return json({ error: 'User not found' }, 404);
    await db.prepare('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?').bind(me.id, peer.id).run();
    return json({ ok: true, blocked: false });
  }
  if (p === 'blocks' && !post) {
    const { results } = await db.prepare('SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,b.created_at FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=? ORDER BY b.created_at DESC LIMIT 200').bind(me.id).all();
    return json({ blocked: results.map(u => ({ ...publicUser(u, now), blocked_at: u.created_at })) });
  }
  if (p === 'report' && post) {
    const peer = await peerOf(body.user_id); if (!peer) return json({ error: 'User not found' }, 404);
    const reason = String(body.reason || ''); if (!REPORT_REASONS.includes(reason)) return json({ error: 'Please choose a reason' }, 400);
    const details = String(body.details || '').trim().slice(0, 500);
    let mid = null, mtext = null;
    if (body.message_id != null) {                            // only a message from the conversation between me and the reported user
      const m = await db.prepare('SELECT id,body,type FROM messages WHERE id=?1 AND ((sender_id=?2 AND receiver_id=?3) OR (sender_id=?3 AND receiver_id=?2)) AND deleted_at IS NULL').bind(Number(body.message_id), me.id, peer.id).first();
      if (!m) return json({ error: 'Message not found' }, 404);
      mid = m.id; mtext = (m.type === 'text' ? m.body : '[' + m.type + '] ' + m.body).slice(0, 500);   // evidence is kept even if the message is deleted later
    }
    const recent = await db.prepare('SELECT COUNT(*) n FROM reports WHERE reporter_id=? AND created_at>?').bind(me.id, now - 864e5).first();
    if (recent.n >= 20) return json({ error: 'Too many reports today. Please try again tomorrow.' }, 429);
    const dup = await db.prepare('SELECT id FROM reports WHERE reporter_id=? AND reported_id=? AND COALESCE(message_id,0)=? AND reason=? AND created_at>?').bind(me.id, peer.id, mid || 0, reason, now - 864e5).first();
    if (!dup) await db.prepare('INSERT INTO reports(reporter_id,reported_id,message_id,message_text,reason,details,created_at) VALUES(?,?,?,?,?,?,?)').bind(me.id, peer.id, mid, mtext, reason, details || null, now).run();
    return json({ ok: true });                                // reports are write-only here: no API returns them, only the database owner can read them
  }

  // ---- status likes + notifications ----
  if (p === 'statuses/like' && post) {
    const s = await visibleStatus(Number(body.id));
    if (!s || s.user_id === me.id) return json({ error: 'Status not found' }, 404);
    const on = body.liked !== false;
    if (on) {
      const r = await db.prepare('INSERT OR IGNORE INTO status_likes(status_id,user_id,created_at) VALUES(?,?,?)').bind(s.id, me.id, now).run();
      if (r.meta.changes) await db.prepare("INSERT OR IGNORE INTO notifications(user_id,type,actor_id,status_id,created_at) VALUES(?,'status_like',?,?,?)").bind(s.user_id, me.id, s.id, now).run();   // one notification per person per status, however often they tap
    } else await db.prepare('DELETE FROM status_likes WHERE status_id=? AND user_id=?').bind(s.id, me.id).run();
    const n = await db.prepare('SELECT COUNT(*) n FROM status_likes WHERE status_id=?').bind(s.id).first();
    return json({ liked: on, likes: n.n });
  }
  if (p === 'statuses/likes' && !post) {
    const id = Number(url.searchParams.get('id'));
    const s = await db.prepare('SELECT id FROM statuses WHERE id=? AND user_id=? AND expires_at>?').bind(id, me.id, now).first();   // only the owner sees who liked
    if (!s) return json({ error: 'Status not found' }, 404);
    const { results } = await db.prepare('SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,l.created_at liked_at FROM status_likes l JOIN users u ON u.id=l.user_id WHERE l.status_id=? ORDER BY l.created_at DESC LIMIT 200').bind(id).all();
    return json({ likes: results.map(v => ({ ...publicUser(v, now), liked_at: v.liked_at })) });
  }
  if (p === 'notifications' && !post) {
    const { results } = await db.prepare(`SELECT n.id,n.type,n.status_id,n.created_at,n.read_at,u.id uid,u.name,u.username,u.avatar_key,u.last_seen,
        EXISTS(SELECT 1 FROM statuses s WHERE s.id=n.status_id AND s.expires_at>?2) available
      FROM notifications n JOIN users u ON u.id=n.actor_id WHERE n.user_id=?1 ORDER BY n.id DESC LIMIT 50`).bind(me.id, now).all();
    const unread = await db.prepare('SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read_at IS NULL').bind(me.id).first();
    return json({ unread: unread.n, notifications: results.map(n => ({ id: n.id, type: n.type, status_id: n.status_id, created_at: n.created_at, read: !!n.read_at, available: !!n.available, user: publicUser({ id: n.uid, name: n.name, username: n.username, avatar_key: n.avatar_key, last_seen: n.last_seen }, now) })) });
  }
  if (p === 'notifications/read' && post) {
    if (body.id != null) await db.prepare('UPDATE notifications SET read_at=? WHERE id=? AND user_id=? AND read_at IS NULL').bind(now, Number(body.id), me.id).run();
    else await db.prepare('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL').bind(now, me.id).run();
    return json({ ok: true });
  }

  // ---- voice calls: WebRTC audio, signaling relayed through D1 (the audio itself never touches the Worker) ----
  if (p.startsWith('calls/')) {
    const sweep = async () => {                             // time out unanswered calls, end calls whose other side stopped sending heartbeats, drop old signals
      const dead = await db.prepare("SELECT id FROM calls WHERE state='ringing' AND created_at<?").bind(now - RING_MS).all();
      await db.prepare("UPDATE calls SET state='missed',ended_at=?1,end_reason='no answer' WHERE state='ringing' AND created_at<?2").bind(now, now - RING_MS).run();
      await db.prepare("UPDATE calls SET state='ended',ended_at=?1,end_reason='connection lost',duration=MAX(0,(?1-answered_at)/1000) WHERE state='active' AND (caller_beat<?2 OR callee_beat<?2)").bind(now, now - BEAT_MS).run();
      await db.prepare('DELETE FROM call_signals WHERE created_at<?').bind(now - 600000).run();
      for (const d of dead.results) await db.prepare('DELETE FROM call_signals WHERE call_id=?').bind(d.id).run();
    };
    const finish = async (c, state, reason) => {            // one row per call: its state is updated in place, never duplicated
      if (c.state !== 'ringing' && c.state !== 'active') return c;
      const dur = c.state === 'active' && c.answered_at ? Math.max(0, Math.round((now - c.answered_at) / 1000)) : 0;
      await db.prepare("UPDATE calls SET state=?,ended_at=?,end_reason=?,duration=? WHERE id=? AND state IN ('ringing','active')").bind(state, now, reason, dur, c.id).run();
      await db.prepare('DELETE FROM call_signals WHERE call_id=?').bind(c.id).run();
      return db.prepare('SELECT * FROM calls WHERE id=?').bind(c.id).first();
    };
    const mine = async id => { const c = await db.prepare('SELECT * FROM calls WHERE id=? AND (caller_id=? OR callee_id=?)').bind(Number(id) || 0, me.id, me.id).first(); return c || null; };
    const view = c => ({ id: c.id, state: c.state, ringing: !!c.ringing_at, video: !!c.video, answered_at: c.answered_at, end_reason: c.end_reason, duration: c.duration, caller_id: c.caller_id, callee_id: c.callee_id });

    if (p === 'calls/ice' && !post) {
      let ice = STUN, turn = false;
      if (env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) {      // TURN credentials are minted per call by Cloudflare from YOUR key; nothing is hard-coded
        try {
          const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, { method: 'POST', headers: { authorization: 'Bearer ' + env.TURN_KEY_API_TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ ttl: 3600 }) });
          if (r.ok) { const d = await r.json(), s = Array.isArray(d.iceServers) ? d.iceServers : d.iceServers ? [d.iceServers] : []; if (s.length) { ice = s; turn = s.some(x => [].concat(x.urls).some(u => /^turns?:/.test(u))); } }
        } catch {}
      }
      if (!turn && env.METERED_APP && env.METERED_API_KEY) {   // alternative free TURN (metered.ca): credentials are fetched with YOUR key
        try {
          const r = await fetch(`https://${encodeURIComponent(env.METERED_APP)}.metered.live/api/v1/turn/credentials?apiKey=${encodeURIComponent(env.METERED_API_KEY)}`);
          if (r.ok) { const s = await r.json(); if (Array.isArray(s) && s.length) { ice = s; turn = s.some(x => [].concat(x.urls).some(u => /^turns?:/.test(u))); } }
        } catch {}
      }
      return json({ iceServers: ice, turn });
    }
    await sweep();
    if (p === 'calls/start' && post) {
      const to = Number(body.to), callee = to && to !== me.id ? await db.prepare('SELECT id,name,username,avatar_key,last_seen FROM users WHERE id=?').bind(to).first() : null;
      if (!callee) return json({ error: 'User not found' }, 404);
      if (await eitherBlocked(me.id, to)) return json({ error: 'You cannot call this user' }, 403);
      const known = await db.prepare('SELECT 1 ok FROM contacts WHERE (owner_id=?1 AND contact_id=?2) OR (owner_id=?2 AND contact_id=?1) UNION SELECT 1 FROM messages WHERE (sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1) LIMIT 1').bind(me.id, to).first();
      if (!known) return json({ error: 'You can only call your contacts' }, 403);
      const busy = await db.prepare("SELECT id FROM calls WHERE state IN ('ringing','active') AND (caller_id IN (?1,?2) OR callee_id IN (?1,?2)) LIMIT 1").bind(me.id, to).first();
      if (busy) return json({ error: 'Line is busy. Try again in a moment.' }, 409);
      const recent = await db.prepare('SELECT COUNT(*) n FROM calls WHERE caller_id=? AND created_at>?').bind(me.id, now - 3600000).first();
      if (recent.n >= 40) return json({ error: 'Too many calls. Please wait a while.' }, 429);
      const r = await db.prepare("INSERT INTO calls(caller_id,callee_id,state,created_at,caller_beat,callee_beat,video) VALUES(?,?,'ringing',?,?,?,?)").bind(me.id, to, now, now, now, body.video ? 1 : 0).run();
      return json({ call: { id: r.meta.last_row_id, state: 'ringing', video: !!body.video }, peer: publicUser(callee, now) });
    }
    if (p === 'calls/poll' && !post) {
      const cid = Number(url.searchParams.get('call_id')) || 0, since = Number(url.searchParams.get('since')) || 0;
      let call = cid ? await mine(cid) : null;
      if (call && call.state === 'active') await db.prepare(`UPDATE calls SET ${call.caller_id === me.id ? 'caller_beat' : 'callee_beat'}=? WHERE id=?`).bind(now, call.id).run();
      if (call && call.state === 'ringing' && call.caller_id === me.id) await db.prepare('UPDATE calls SET caller_beat=? WHERE id=?').bind(now, call.id).run();
      const inc = await db.prepare("SELECT c.*,u.name,u.username,u.avatar_key,u.last_seen FROM calls c JOIN users u ON u.id=c.caller_id WHERE c.callee_id=? AND c.state='ringing' ORDER BY c.id DESC LIMIT 1").bind(me.id).first();
      if (inc && !inc.ringing_at) await db.prepare('UPDATE calls SET ringing_at=? WHERE id=?').bind(now, inc.id).run();   // the caller now sees "Ringing"
      const sig = call && (call.state === 'ringing' || call.state === 'active') ? (await db.prepare('SELECT id,kind,payload FROM call_signals WHERE call_id=? AND to_user=? AND id>? ORDER BY id LIMIT 100').bind(call.id, me.id, since).all()).results : [];
      if (cid) call = await mine(cid);
      return json({ incoming: inc ? { id: inc.id, video: !!inc.video, from: publicUser({ id: inc.caller_id, name: inc.name, username: inc.username, avatar_key: inc.avatar_key, last_seen: inc.last_seen }, now) } : null, call: call ? view(call) : null, signals: sig });
    }
    if (p === 'calls/answer' && post) {
      const c = await mine(body.id); if (!c || c.callee_id !== me.id) return json({ error: 'Call not found' }, 404);
      if (c.state !== 'ringing') return json({ error: 'This call has ended', call: view(c) }, 409);
      await db.prepare("UPDATE calls SET state='active',answered_at=?1,caller_beat=?1,callee_beat=?1 WHERE id=? AND state='ringing'").bind(now, c.id).run();
      return json({ call: view(await mine(c.id)) });
    }
    if (p === 'calls/reject' && post) {
      const c = await mine(body.id); if (!c || c.callee_id !== me.id) return json({ error: 'Call not found' }, 404);
      return json({ call: view(await finish(c, 'rejected', 'declined')) });
    }
    if (p === 'calls/end' && post) {                        // idempotent: ending a finished call changes nothing
      const c = await mine(body.id); if (!c) return json({ error: 'Call not found' }, 404);
      const reason = ['hangup', 'failed', 'connection lost'].includes(body.reason) ? body.reason : 'hangup';
      const state = c.state === 'ringing' ? (c.caller_id === me.id ? 'missed' : 'rejected') : reason === 'failed' ? 'failed' : 'ended';
      return json({ call: view(await finish(c, state, c.state === 'ringing' ? (c.caller_id === me.id ? 'cancelled' : 'declined') : reason)) });
    }
    if (p === 'calls/signal' && post) {
      const c = await mine(body.id); if (!c) return json({ error: 'Call not found' }, 404);
      if (c.state !== 'ringing' && c.state !== 'active') return json({ error: 'This call has ended', call: view(c) }, 409);
      const kind = String(body.kind || ''), payload = typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload || null);
      if (!['offer', 'answer', 'ice', 'cam'].includes(kind) || payload.length > 16000) return json({ error: 'Invalid signal' }, 400);
      if ((kind === 'offer' && c.caller_id !== me.id) || (kind === 'answer' && c.callee_id !== me.id)) return json({ error: 'Not allowed' }, 403);
      if (kind !== 'ice' && kind !== 'cam' && c.state !== 'active') return json({ error: 'Call not accepted yet' }, 409);
      await db.prepare('INSERT INTO call_signals(call_id,to_user,kind,payload,created_at) VALUES(?,?,?,?,?)').bind(c.id, c.caller_id === me.id ? c.callee_id : c.caller_id, kind, payload, now).run();
      return json({ ok: true });
    }
    if (p === 'calls/history' && !post) {
      const w = url.searchParams.get('with');
      if (w !== null) {                                      // calls with ONE person (shown inside that chat); respects "Clear chat"
        const peerId = parseInt(w, 10); if (!Number.isInteger(peerId)) return json({ error: 'User not found' }, 404);
        const pf = await db.prepare('SELECT cleared_at FROM chat_prefs WHERE user_id=? AND peer_id=?').bind(me.id, peerId).first();
        const { results } = await db.prepare(`SELECT id,caller_id,state,video,created_at,duration FROM calls WHERE ((caller_id=?1 AND callee_id=?2) OR (caller_id=?2 AND callee_id=?1)) AND state NOT IN ('ringing','active') AND created_at>?3 ORDER BY id DESC LIMIT 100`).bind(me.id, peerId, (pf && pf.cleared_at) || 0).all();
        return json({ calls: results.reverse().map(c => ({ id: c.id, direction: c.caller_id === me.id ? 'out' : 'in', video: !!c.video, state: c.state, created_at: c.created_at, duration: c.duration })) });
      }
      const { results } = await db.prepare(`SELECT c.id,c.caller_id,c.state,c.video,c.created_at,c.duration,u.id uid,u.name,u.username,u.avatar_key,u.last_seen FROM calls c JOIN users u ON u.id=CASE WHEN c.caller_id=?1 THEN c.callee_id ELSE c.caller_id END WHERE (c.caller_id=?1 OR c.callee_id=?1) AND c.state!='ringing' ORDER BY c.id DESC LIMIT 100`).bind(me.id).all();
      return json({ calls: results.map(c => ({ id: c.id, direction: c.caller_id === me.id ? 'out' : 'in', video: !!c.video, state: c.state, created_at: c.created_at, duration: c.duration, peer: publicUser({ id: c.uid, name: c.name, username: c.username, avatar_key: c.avatar_key, last_seen: c.last_seen }, now) })) });
    }
    return json({ error: 'Not found' }, 404);
  }

  if (p === 'chats') {
    await db.prepare('UPDATE messages SET delivered_at=? WHERE receiver_id=? AND delivered_at IS NULL').bind(now, me.id).run();
    const { results } = await db.prepare(`
      SELECT u.id,u.name,u.avatar_key,u.last_seen,m.body last_body,m.type last_type,m.created_at last_at,m.sender_id last_sender,m.read_at last_read,m.delivered_at last_delivered,
        m.deleted_at last_deleted,
        (SELECT COUNT(*) FROM messages x WHERE x.sender_id=u.id AND x.receiver_id=?1 AND x.read_at IS NULL AND x.id>COALESCE((SELECT cleared_id FROM chat_prefs WHERE user_id=?1 AND peer_id=u.id),0)) unread
      FROM users u JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE ((sender_id=?1 AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=?1)) AND id>COALESCE((SELECT cleared_id FROM chat_prefs WHERE user_id=?1 AND peer_id=u.id),0))
      WHERE u.id!=?1 ORDER BY m.id DESC LIMIT 200`).bind(me.id).all();
    return json({ chats: results.map(c => ({ ...c, avatar: c.avatar_key || null, avatar_key: undefined, online: now - c.last_seen < ONLINE_MS, last_seen: undefined })) });
  }

  if (p === 'messages' && !post) {
    const peerId = parseInt(url.searchParams.get('with'), 10);
    if (!Number.isInteger(peerId)) return json({ error: 'User not found' }, 404);
    const peer = await db.prepare('SELECT id,last_seen FROM users WHERE id=?').bind(peerId).first();
    if (!peer) return json({ error: 'User not found' }, 404);
    await db.prepare('UPDATE messages SET read_at=?1, delivered_at=COALESCE(delivered_at,?1) WHERE sender_id=?2 AND receiver_id=?3 AND read_at IS NULL').bind(now, peerId, me.id).run();
    const { results } = await db.prepare(`
      SELECT id,sender_id,body,type,media_key,media_type,media_size,duration,reply_to,created_at,delivered_at,read_at,deleted_at,status_id,status_snap FROM (
        SELECT * FROM messages WHERE ((sender_id=?1 AND receiver_id=?2) OR (sender_id=?2 AND receiver_id=?1)) AND id>?3 ORDER BY id DESC LIMIT 200
      ) ORDER BY id`).bind(me.id, peerId, await clearedId(peerId)).all();
    const pref = await db.prepare('SELECT theme FROM chat_prefs WHERE user_id=? AND peer_id=?').bind(me.id, peerId).first();
    let theme = null; if (pref && pref.theme) try { theme = JSON.parse(pref.theme); } catch {}
    const blocked = !!(await iBlocked(me.id, peerId));
    const messages = results.map(({ status_snap, ...m }) => { let st = null; if (status_snap && !m.deleted_at) try { st = JSON.parse(status_snap); } catch {} return { ...m, status: st }; });   // private status-reply preview
    return json({ messages, theme, blocked, online: now - peer.last_seen < ONLINE_MS, last_seen: peer.last_seen });
  }

  if (p === 'messages' && post) {
    const to = Number(body.to), text = String(body.body || '').trim();
    const type = ['text', 'image', 'voice', 'video'].includes(body.type) ? body.type : 'text';
    if (text.length > 2000 || (type === 'text' && !text)) return json({ error: 'Message must be 1–2000 characters' }, 400);
    if (!Number.isInteger(to) || to === me.id || !(await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())) return json({ error: 'User not found' }, 404);
    if (await eitherBlocked(me.id, to)) return json({ error: (await iBlocked(me.id, to)) ? 'You blocked this user. Unblock them to send messages.' : 'You cannot send messages to this user.' }, 403);
    let key = null, mtype = null, msize = null, dur = null, replyTo = null;
    if (type !== 'text') {
      key = String(body.media_key || '');
      if (!MEDIA_KEY.test(key) || !key.startsWith('u' + me.id + '/')) return json({ error: 'Invalid media' }, 400);   // only your own uploads
      const up = await db.prepare('SELECT type,size FROM media WHERE key=? AND owner_id=?').bind(key, me.id).first();
      if (!up) return json({ error: 'Upload not found. Please try again.' }, 400);
      mtype = up.type;
      if (!mtype.startsWith(type === 'image' ? 'image/' : type === 'video' ? 'video/' : 'audio/')) return json({ error: 'Media type does not match' }, 400);
      if (await db.prepare('SELECT id FROM messages WHERE media_key=?').bind(key).first() || await db.prepare('SELECT id FROM users WHERE avatar_key=?').bind(key).first() || await db.prepare('SELECT id FROM statuses WHERE media_key=?').bind(key).first()) return json({ error: 'Media already used' }, 409);
      msize = up.size; dur = type === 'voice' || type === 'video' ? Math.min(3600, Math.max(0, Math.round(Number(body.duration) || 0))) : null;
    }
    if (body.reply_to != null) {
      const rid = Number(body.reply_to);
      if (Number.isInteger(rid) && await db.prepare('SELECT id FROM messages WHERE id=?1 AND ((sender_id=?2 AND receiver_id=?3) OR (sender_id=?3 AND receiver_id=?2))').bind(rid, me.id, to).first()) replyTo = rid;
    }
    let stId = null, snap = null;
    if (body.status_id != null) {                           // this message is a PRIVATE reply to someone's status
      const s = await visibleStatus(Number(body.status_id));       // same rule as viewing: owner or mutual contact, not expired
      if (!s || s.user_id !== to || s.user_id === me.id) return json({ error: 'This status is no longer available' }, 404);
      const th = typeof body.thumb === 'string' && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]{20,12000}$/.test(body.thumb) ? body.thumb : null;
      stId = s.id; snap = JSON.stringify({ t: s.type, x: String(s.type === 'text' ? s.body : s.caption || '').slice(0, 120), bg: s.bg, th });
    }
    const r = await db.prepare('INSERT INTO messages(sender_id,receiver_id,body,created_at,type,media_key,media_type,media_size,duration,reply_to,status_id,status_snap) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(me.id, to, text, now, type, key, mtype, msize, dur, replyTo, stId, snap).run();
    return json({ id: r.meta.last_row_id, created_at: now });
  }

  // delete my own message for everyone (media is removed from storage too)
  if (p === 'messages/delete' && post) {
    const id = Number(body.id);
    const m = Number.isInteger(id) ? await db.prepare('SELECT id,media_key FROM messages WHERE id=? AND sender_id=? AND deleted_at IS NULL').bind(id, me.id).first() : null;
    if (!m) return json({ error: 'Message not found' }, 404);
    await db.prepare("UPDATE messages SET deleted_at=?, body='', media_key=NULL, status_id=NULL, status_snap=NULL WHERE id=?").bind(now, id).run();
    if (m.media_key) await dropAny(m.media_key);
    return json({ ok: true });
  }


  // ---- status (24h) : text or photo; visible to the owner and to the people the owner has saved as contacts ----
  const STATUS_MS = 864e5, STATUS_MAX = 30;
  const shapeStatus = s => ({ id: s.id, type: s.type, body: s.body || '', caption: s.caption || '', bg: s.bg || 0, media: s.media_key || null, created_at: s.created_at, expires_at: s.expires_at });
  const dropStatuses = async rows => {                       // remove rows + their views + their photos
    for (const s of rows) {
      const st = [db.prepare('DELETE FROM status_views WHERE status_id=?').bind(s.id), db.prepare('DELETE FROM status_likes WHERE status_id=?').bind(s.id), db.prepare('DELETE FROM notifications WHERE status_id=?').bind(s.id), db.prepare('DELETE FROM statuses WHERE id=?').bind(s.id)];
      await db.batch(st);
      if (s.media_key) await dropAny(s.media_key);
    }
  };
  if (p === 'statuses' && !post) {
    const mine = (await db.prepare('SELECT s.*,(SELECT COUNT(*) FROM status_views v WHERE v.status_id=s.id) views,(SELECT COUNT(*) FROM status_likes l WHERE l.status_id=s.id) likes FROM statuses s WHERE s.user_id=? AND s.expires_at>? ORDER BY s.id').bind(me.id, now).all()).results;
    const feed = (await db.prepare(`SELECT s.*,u.name,u.username,u.avatar_key,u.last_seen,
        EXISTS(SELECT 1 FROM status_views v WHERE v.status_id=s.id AND v.viewer_id=?1) seen,
        (SELECT COUNT(*) FROM status_likes l WHERE l.status_id=s.id) likes, EXISTS(SELECT 1 FROM status_likes l WHERE l.status_id=s.id AND l.user_id=?1) liked
      FROM statuses s JOIN users u ON u.id=s.user_id JOIN contacts c ON c.owner_id=s.user_id AND c.contact_id=?1 JOIN contacts c2 ON c2.owner_id=?1 AND c2.contact_id=s.user_id   -- mutual: they saved me AND I saved them
      WHERE s.expires_at>?2 AND s.user_id!=?1 AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=s.user_id AND b.blocked_id=?1) OR (b.blocker_id=?1 AND b.blocked_id=s.user_id)) ORDER BY s.user_id, s.id LIMIT 300`).bind(me.id, now).all()).results;
    const groups = new Map();
    for (const s of feed) {
      if (!groups.has(s.user_id)) groups.set(s.user_id, { user: publicUser({ id: s.user_id, name: s.name, username: s.username, avatar_key: s.avatar_key, last_seen: s.last_seen }, now), items: [] });
      groups.get(s.user_id).items.push({ ...shapeStatus(s), seen: !!s.seen, likes: s.likes, liked: !!s.liked });
    }
    const users = [...groups.values()].map(g => ({ ...g, unseen: g.items.filter(i => !i.seen).length, latest: g.items[g.items.length - 1].created_at }));
    users.sort((a, b) => (b.unseen > 0) - (a.unseen > 0) || b.latest - a.latest);
    return json({ mine: mine.map(s => ({ ...shapeStatus(s), views: s.views, likes: s.likes })), users });
  }
  if (p === 'statuses' && post) {
    const type = ['image', 'text', 'video'].includes(body.type) ? body.type : null;
    if (!type) return json({ error: 'Status must be a photo, video or text' }, 400);
    const stale = (await db.prepare('SELECT id,media_key FROM statuses WHERE expires_at<=? LIMIT 25').bind(now).all()).results;
    if (stale.length) await dropStatuses(stale);             // housekeeping: expired statuses and their photos are deleted for good
    if ((await db.prepare('SELECT COUNT(*) n FROM statuses WHERE user_id=? AND expires_at>?').bind(me.id, now).first()).n >= STATUS_MAX) return json({ error: 'You can have up to 30 active statuses' }, 429);
    let text = null, cap = null, bg = 0, key = null;
    if (type === 'text') {
      text = String(body.body ?? '').trim(); bg = Number.isInteger(body.bg) ? Math.min(7, Math.max(0, body.bg)) : 0;
      if (!text || text.length > 700) return json({ error: 'Status text must be 1–700 characters' }, 400);
    } else {
      key = String(body.key || ''); cap = String(body.caption ?? '').trim().slice(0, 200);
      if (!MEDIA_KEY.test(key) || !key.startsWith('u' + me.id + '/')) return json({ error: 'Invalid photo' }, 400);
      const up = await db.prepare('SELECT type FROM media WHERE key=? AND owner_id=?').bind(key, me.id).first();
      if (!up || !up.type.startsWith(type === 'video' ? 'video/' : 'image/')) return json({ error: 'Upload not found. Please try again.' }, 400);
      if (await db.prepare('SELECT id FROM messages WHERE media_key=?').bind(key).first() || await db.prepare('SELECT id FROM users WHERE avatar_key=?').bind(key).first() || await db.prepare('SELECT id FROM statuses WHERE media_key=?').bind(key).first()) return json({ error: 'Media already used' }, 409);
    }
    const r = await db.prepare('INSERT INTO statuses(user_id,type,body,caption,bg,media_key,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)').bind(me.id, type, text, cap, bg, key, now, now + STATUS_MS).run();
    return json({ status: { id: r.meta.last_row_id, type, body: text || '', caption: cap || '', bg, media: key, created_at: now, expires_at: now + STATUS_MS, views: 0 } });
  }
  if (p === 'statuses/view' && post) {
    const s = await visibleStatus(Number(body.id));
    if (!s) return json({ error: 'Status not found' }, 404);
    if (s.user_id !== me.id) await db.prepare('INSERT OR IGNORE INTO status_views(status_id,viewer_id,viewed_at) VALUES(?,?,?)').bind(s.id, me.id, now).run();
    return json({ ok: true });
  }
  if (p === 'statuses/viewers' && !post) {
    const id = Number(url.searchParams.get('id'));
    const s = await db.prepare('SELECT id FROM statuses WHERE id=? AND user_id=? AND expires_at>?').bind(id, me.id, now).first();   // only the owner may see who viewed
    if (!s) return json({ error: 'Status not found' }, 404);
    const { results } = await db.prepare('SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,v.viewed_at FROM status_views v JOIN users u ON u.id=v.viewer_id WHERE v.status_id=? ORDER BY v.viewed_at DESC LIMIT 200').bind(id).all();
    return json({ viewers: results.map(v => ({ ...publicUser(v, now), viewed_at: v.viewed_at })) });
  }
  if (p === 'statuses/delete' && post) {
    const s = await db.prepare('SELECT id,media_key FROM statuses WHERE id=? AND user_id=?').bind(Number(body.id), me.id).first();
    if (!s) return json({ error: 'Status not found' }, 404);
    await dropStatuses([s]);
    return json({ ok: true });
  }

  // ---- profile photo (uses a previous /api/media upload of kind "image") ----
  const dropMedia = key => db.batch([db.prepare('DELETE FROM media_chunks WHERE key=?').bind(key), db.prepare('DELETE FROM media WHERE key=?').bind(key)]);
  if (p === 'profile/avatar' && post) {
    const key = String(body.key || '');
    if (!MEDIA_KEY.test(key) || !key.startsWith('u' + me.id + '/')) return json({ error: 'Invalid photo' }, 400);
    const up = await db.prepare('SELECT type,size FROM media WHERE key=? AND owner_id=?').bind(key, me.id).first();
    if (!up || !up.type.startsWith('image/')) return json({ error: 'Upload not found. Please try again.' }, 400);
    if (up.size > 250000) return json({ error: 'Profile photo is too large' }, 413);
    if (await db.prepare('SELECT id FROM messages WHERE media_key=?').bind(key).first() || await db.prepare('SELECT id FROM statuses WHERE media_key=?').bind(key).first()) return json({ error: 'Media already used' }, 409);
    const prev = await db.prepare('SELECT avatar_key FROM users WHERE id=?').bind(me.id).first();
    await db.prepare('UPDATE users SET avatar_key=? WHERE id=?').bind(key, me.id).run();
    if (prev && prev.avatar_key && prev.avatar_key !== key) await dropMedia(prev.avatar_key);
    return json({ avatar: key });
  }
  if (p === 'profile/avatar/remove' && post) {
    const prev = await db.prepare('SELECT avatar_key FROM users WHERE id=?').bind(me.id).first();
    await db.prepare('UPDATE users SET avatar_key=NULL WHERE id=?').bind(me.id).run();
    if (prev && prev.avatar_key) await dropMedia(prev.avatar_key);
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
      db.prepare('DELETE FROM media_chunks WHERE key IN (SELECT key FROM media WHERE owner_id=? AND created_at<? AND key NOT IN (SELECT media_key FROM messages WHERE media_key IS NOT NULL) AND key NOT IN (SELECT avatar_key FROM users WHERE avatar_key IS NOT NULL) AND key NOT IN (SELECT media_key FROM statuses WHERE media_key IS NOT NULL))').bind(me.id, old),
      db.prepare('DELETE FROM media WHERE owner_id=? AND created_at<? AND key NOT IN (SELECT media_key FROM messages WHERE media_key IS NOT NULL) AND key NOT IN (SELECT avatar_key FROM users WHERE avatar_key IS NOT NULL) AND key NOT IN (SELECT media_key FROM statuses WHERE media_key IS NOT NULL)').bind(me.id, old)
    ]);
    const key = `u${me.id}/${rand(16)}`, stmts = [db.prepare('INSERT INTO media(key,owner_id,type,size,created_at) VALUES(?,?,?,?,?)').bind(key, me.id, type, size, now)];
    for (let i = 0, n = 0; i < data.length; i += CHUNK, n++) stmts.push(db.prepare('INSERT INTO media_chunks(key,idx,data) VALUES(?,?,?)').bind(key, n, data.slice(i, i + CHUNK)));
    await db.batch(stmts);
    return json({ key, size, type });
  }

  // ---- video upload: raw bytes -> R2 (only when the MEDIA bucket binding exists) ----
  if (p === 'video' && post) {
    if (!env.MEDIA) return json({ error: 'Video storage (R2) is not set up yet' }, 501);
    const len = Number(req.headers.get('content-length') || 0);
    if (!len) return json({ error: 'Invalid file' }, 400);
    if (len > VIDEO_MAX) return json({ error: 'Video is too large (max 20 MB)' }, 413);
    const buf = await req.arrayBuffer();
    if (buf.byteLength > VIDEO_MAX) return json({ error: 'Video is too large (max 20 MB)' }, 413);
    if (buf.byteLength < 32) return json({ error: 'Invalid file' }, 400);
    const h = new Uint8Array(buf.slice(0, 16)), at = (i, s) => [...s].every((c, j) => h[i + j] === c.charCodeAt(0));
    const type = at(4, 'ftyp') ? 'video/mp4' : (h[0] === 0x1A && h[1] === 0x45 && h[2] === 0xDF && h[3] === 0xA3) ? 'video/webm' : null;   // real file signature, never the client's claim
    if (!type) return json({ error: 'This video format is not allowed (use MP4 or WebM)' }, 415);
    const old = now - 3600000;                              // tidy up this user's videos that were never sent
    const stale = (await db.prepare("SELECT key FROM media WHERE owner_id=? AND created_at<? AND type LIKE 'video/%' AND key NOT IN (SELECT media_key FROM messages WHERE media_key IS NOT NULL) AND key NOT IN (SELECT media_key FROM statuses WHERE media_key IS NOT NULL) LIMIT 10").bind(me.id, old).all()).results;
    for (const s of stale) await dropAny(s.key);
    const key = `u${me.id}/${rand(16)}`;
    await env.MEDIA.put(key, buf, { httpMetadata: { contentType: type } });
    await db.prepare('INSERT INTO media(key,owner_id,type,size,created_at) VALUES(?,?,?,?,?)').bind(key, me.id, type, buf.byteLength, now).run();
    return json({ key, size: buf.byteLength, type });
  }

  if (p.startsWith('media/') && !post) {
    const key = p.slice(6);
    if (!MEDIA_KEY.test(key)) return json({ error: 'Not found' }, 404);
    const allowed = key.startsWith('u' + me.id + '/') ||
      await db.prepare('SELECT 1 ok FROM messages WHERE media_key=? AND deleted_at IS NULL AND (sender_id=? OR receiver_id=?)').bind(key, me.id, me.id).first() ||
      await db.prepare('SELECT 1 ok FROM users WHERE avatar_key=?').bind(key).first() ||   // profile photos
      await db.prepare('SELECT 1 ok FROM statuses s WHERE s.media_key=? AND s.expires_at>? AND (s.user_id=?3 OR (EXISTS(SELECT 1 FROM contacts c WHERE c.owner_id=s.user_id AND c.contact_id=?3) AND EXISTS(SELECT 1 FROM contacts c2 WHERE c2.owner_id=?3 AND c2.contact_id=s.user_id) AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=s.user_id AND b.blocked_id=?3) OR (b.blocker_id=?3 AND b.blocked_id=s.user_id))))').bind(key, now, me.id).first();   // status media: owner and MUTUAL contacts only
    const m = allowed ? await db.prepare('SELECT type FROM media WHERE key=?').bind(key).first() : null;
    if (!m) return json({ error: 'Not found' }, 404);
    if (m.type.startsWith('video/')) {                      // videos stream straight from R2 (same permission check as above)
      const obj = env.MEDIA ? await env.MEDIA.get(key) : null;
      if (!obj) return json({ error: 'Not found' }, 404);
      return new Response(obj.body, { headers: { 'content-type': m.type, 'content-length': String(obj.size), 'cache-control': 'private, no-store', ...CORS } });
    }
    const { results } = await db.prepare('SELECT data FROM media_chunks WHERE key=? ORDER BY idx').bind(key).all();
    return json({ type: m.type, data: results.map(r => r.data).join('') });
  }

  return json({ error: 'Not found' }, 404);
}
