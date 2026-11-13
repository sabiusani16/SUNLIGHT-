// SUNLIGHT API — Cloudflare Worker + D1 (binding: DB)
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const ONLINE_MS = 30000, SESSION_MS = 30 * 864e5;

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try { return await route(req, env, url); }
    catch (e) { return json({ error: 'Server error' }, 500); }
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

  if (p === 'register' && post) {
    const username = String(body.username || '').trim().toLowerCase();
    const name = String(body.name || '').trim();
    const pw = String(body.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return json({ error: 'Username: 3–20 letters, numbers or _' }, 400);
    if (!name || name.length > 40) return json({ error: 'Enter your name (max 40 characters)' }, 400);
    if (pw.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);
    const salt = rand(16);
    let r;
    try {
      r = await db.prepare('INSERT INTO users(username,name,pass_hash,salt,created_at,last_seen) VALUES(?,?,?,?,?,?)')
        .bind(username, name, await hashPw(pw, salt), salt, now, now).run();
    } catch { return json({ error: 'Username already taken' }, 409); }
    return startSession(db, { id: r.meta.last_row_id, username, name }, now);
  }

  if (p === 'login' && post) {
    const username = String(body.username || '').trim().toLowerCase();
    const u = await db.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
    if (!u || await hashPw(String(body.password || ''), u.salt) !== u.pass_hash) return json({ error: 'Wrong username or password' }, 401);
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

  if (p === 'users') {
    const { results } = await db.prepare('SELECT id,name,username,last_seen FROM users WHERE id!=? ORDER BY name LIMIT 200').bind(me.id).all();
    return json({ users: results.map(u => ({ id: u.id, name: u.name, username: u.username, online: now - u.last_seen < ONLINE_MS })) });
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
    if (to === me.id || !(await db.prepare('SELECT id FROM users WHERE id=?').bind(to).first())) return json({ error: 'User not found' }, 404);
    const r = await db.prepare('INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)').bind(me.id, to, text, now).run();
    return json({ id: r.meta.last_row_id });
  }

  return json({ error: 'Not found' }, 404);
}
