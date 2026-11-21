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
const APP_VERSION = '1.0.0';
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const likeEsc = s => s.replace(/[\\%_]/g, '\\$&');            // escape LIKE wildcards in user input
const REFS = '(SELECT media_key FROM messages WHERE media_key IS NOT NULL UNION SELECT json_extract(theme,\'$.wp\') FROM chat_prefs WHERE theme IS NOT NULL AND json_extract(theme,\'$.wp\') IS NOT NULL UNION SELECT avatar_key FROM users WHERE avatar_key IS NOT NULL UNION SELECT media_key FROM statuses WHERE media_key IS NOT NULL UNION SELECT media_key FROM group_messages WHERE media_key IS NOT NULL UNION SELECT avatar_key FROM groups WHERE avatar_key IS NOT NULL UNION SELECT media_key FROM channel_posts WHERE media_key IS NOT NULL UNION SELECT avatar_key FROM channels WHERE avatar_key IS NOT NULL UNION SELECT wp_key FROM chat_prefs WHERE wp_key IS NOT NULL)';
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
  `CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', avatar_key TEXT, created_by INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL, added_by INTEGER, PRIMARY KEY (group_id, user_id))`,
  `CREATE INDEX IF NOT EXISTS idx_gm_user ON group_members(user_id)`,
  `CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, body TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT 'text', media_key TEXT, media_type TEXT, media_size INTEGER, duration INTEGER, reply_to INTEGER, created_at INTEGER NOT NULL, deleted_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id, id)`,
  `CREATE TABLE IF NOT EXISTS group_reactions (message_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (message_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS group_reads (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, last_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (group_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', avatar_key TEXT, owner_id INTEGER NOT NULL, visibility TEXT NOT NULL DEFAULT 'public', comments_on INTEGER NOT NULL DEFAULT 1, invite_code TEXT, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS channel_members (channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'subscriber', joined_at INTEGER NOT NULL, last_seen_post INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, user_id))`,
  `CREATE INDEX IF NOT EXISTS idx_cm_user ON channel_members(user_id)`,
  `CREATE TABLE IF NOT EXISTS channel_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id INTEGER NOT NULL, author_id INTEGER NOT NULL, body TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT 'text', media_key TEXT, media_type TEXT, media_size INTEGER, duration INTEGER, created_at INTEGER NOT NULL, edited_at INTEGER, deleted_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_cp_channel ON channel_posts(channel_id, id)`,
  `CREATE TABLE IF NOT EXISTS channel_reactions (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (post_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS channel_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, deleted_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_cc_post ON channel_comments(post_id, id)`,
  `CREATE TABLE IF NOT EXISTS otp_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, purpose TEXT NOT NULL, user_id INTEGER, code_hash TEXT NOT NULL, salt TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, consumed_at INTEGER, ip_hash TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_requests(phone, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_otp_ip ON otp_requests(ip_hash, created_at)`,
  `CREATE TABLE IF NOT EXISTS signup_tickets (hash TEXT PRIMARY KEY, phone TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS auth_fails (k TEXT NOT NULL, at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_auth_fails ON auth_fails(k, at)`,
  `CREATE TABLE IF NOT EXISTS user_prefs (user_id INTEGER PRIMARY KEY, notif TEXT, updated_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS email_changes (user_id INTEGER PRIMARY KEY, new_email TEXT NOT NULL, code_hash TEXT NOT NULL, salt TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS support_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_support_user ON support_requests(user_id, id)`,
  `CREATE TABLE IF NOT EXISTS status_views (status_id INTEGER NOT NULL, viewer_id INTEGER NOT NULL, viewed_at INTEGER NOT NULL, PRIMARY KEY (status_id, viewer_id))`
];
const USER_COLS = { phone: 'TEXT', phone_verified_at: 'INTEGER', username: "TEXT", email: 'TEXT', name: "TEXT NOT NULL DEFAULT ''", pass_hash: "TEXT NOT NULL DEFAULT ''", salt: "TEXT NOT NULL DEFAULT ''", created_at: 'INTEGER NOT NULL DEFAULT 0', last_seen: 'INTEGER NOT NULL DEFAULT 0', avatar_key: 'TEXT' };
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
    await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL').run();
    const haveS = (await db.prepare('PRAGMA table_info(sessions)').all()).results.map(c => c.name);
    if (!haveS.includes('last_used')) await addCol(db, 'sessions', 'last_used', 'INTEGER NOT NULL DEFAULT 0');
    if (!haveS.includes('ua')) await addCol(db, 'sessions', 'ua', 'TEXT');
    const haveM = (await db.prepare('PRAGMA table_info(messages)').all()).results.map(c => c.name);
    for (const [col, type] of Object.entries(MSG_COLS)) if (!haveM.includes(col)) await addCol(db, 'messages', col, type);
    const haveC = (await db.prepare('PRAGMA table_info(calls)').all()).results.map(c => c.name);
    if (!haveC.includes('video')) await addCol(db, 'calls', 'video', 'INTEGER NOT NULL DEFAULT 0');
    const haveP = (await db.prepare('PRAGMA table_info(chat_prefs)').all()).results.map(c => c.name);
    if (!haveP.includes('wp_key')) await addCol(db, 'chat_prefs', 'wp_key', 'TEXT');
    if (!haveP.includes('wp_dim')) await addCol(db, 'chat_prefs', 'wp_dim', 'INTEGER NOT NULL DEFAULT 35');
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
      const out = {};
      let res = await route(req, env, url, out);
      if (out.cookie) { res = new Response(res.body, res); res.headers.append('set-cookie', out.cookie); }
      return res;
    } catch (e) {
      const msg = String(e && e.message || e), ref = rand(3);
      console.error(`[SUNLIGHT ${ref}]`, msg);
      try {                                                   // keep the last 100 server errors so the owner can look a ref up: SELECT * FROM error_log ORDER BY id DESC LIMIT 10;
        await env.DB.prepare('CREATE TABLE IF NOT EXISTS error_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT, route TEXT, message TEXT, created_at INTEGER)').run();
        await env.DB.prepare('INSERT INTO error_log(ref,route,message,created_at) VALUES(?,?,?,?)').bind(ref, req.method + ' ' + url.pathname, msg.slice(0, 500), Date.now()).run();
        await env.DB.prepare('DELETE FROM error_log WHERE id <= (SELECT MAX(id) FROM error_log) - 100').run();
      } catch {}
      if (env.DEBUG_ERRORS !== '0') return json({ error: `Server error (ref ${ref}): ${msg.slice(0, 160)}`, code: 'SERVER' }, 500);   // TEMPORARY: shows the cause while we hunt a bug. Set Worker variable DEBUG_ERRORS=0 to hide it again
      if (/no such table|no such column/i.test(msg)) return json({ error: 'Database tables are missing. Run: wrangler d1 execute DB --remote --file=schema.sql', code: 'DB_SCHEMA' }, 500);
      return json({ error: `Server error (ref ${ref}). Please try again.`, code: 'SERVER' }, 500);
    }
  }
};


const NOTIF_DEFAULTS = { messages: true, groups: true, channels: true, calls: true, sound: true, tone: 'default', vibrate: true, status_likes: true, status_replies: true, status_activity: true, browser: false };
const TONES = ['default', 'chime', 'bell', 'pop', 'gold', 'soft'];
const RESERVED = new Set(['admin', 'administrator', 'support', 'sunlight', 'root', 'system', 'help', 'moderator', 'staff', 'official']);
const sha = async s => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
const cleanPrefs = raw => {                                  // only known keys, strict types: anything else is ignored
  const out = { ...NOTIF_DEFAULTS }; let o = raw; if (typeof o === 'string') { try { o = JSON.parse(o); } catch { o = {}; } }
  if (o && typeof o === 'object') for (const k of Object.keys(NOTIF_DEFAULTS)) {
    if (k === 'tone') { if (TONES.includes(o.tone)) out.tone = o.tone; } else if (typeof o[k] === 'boolean') out[k] = o[k];
  }
  return out;
};
async function sendMail(env, to, subject, text) {            // needs RESEND_API_KEY + MAIL_FROM (Worker secrets); never invents a provider
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: 'Bearer ' + env.RESEND_API_KEY, 'content-type': 'application/json' }, body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text }) });
    return r.ok;
  } catch { return false; }
}


// ---------- PHONE NUMBERS (E.164) ----------
// [ISO, name, calling code, min national digits, max national digits, strips a leading trunk "0"]
const COUNTRIES = [["NG","Nigeria","234",10,10,1],["GH","Ghana","233",9,9,1],["NE","Niger","227",8,8,0],["TD","Chad","235",8,8,0],["CM","Cameroon","237",9,9,0],["BJ","Benin","229",8,10,0],["TG","Togo","228",8,8,0],["BF","Burkina Faso","226",8,8,0],["ML","Mali","223",8,8,0],["SN","Senegal","221",9,9,0],["CI","Côte d’Ivoire","225",8,10,0],["LR","Liberia","231",7,9,1],["SL","Sierra Leone","232",8,8,1],["GM","Gambia","220",7,7,0],["GN","Guinea","224",9,9,0],["MR","Mauritania","222",8,8,0],["KE","Kenya","254",9,9,1],["UG","Uganda","256",9,9,1],["TZ","Tanzania","255",9,9,1],["RW","Rwanda","250",9,9,0],["ET","Ethiopia","251",9,9,1],["ZA","South Africa","27",9,9,1],["ZW","Zimbabwe","263",9,9,1],["ZM","Zambia","260",9,9,1],["AO","Angola","244",9,9,0],["MZ","Mozambique","258",9,9,0],["EG","Egypt","20",10,10,1],["MA","Morocco","212",9,9,1],["DZ","Algeria","213",9,9,1],["TN","Tunisia","216",8,8,0],["LY","Libya","218",9,9,1],["SD","Sudan","249",9,9,1],["SO","Somalia","252",7,9,0],["GB","United Kingdom","44",10,10,1],["IE","Ireland","353",9,9,1],["FR","France","33",9,9,1],["DE","Germany","49",10,11,1],["ES","Spain","34",9,9,0],["IT","Italy","39",9,10,0],["PT","Portugal","351",9,9,0],["NL","Netherlands","31",9,9,1],["BE","Belgium","32",9,9,1],["CH","Switzerland","41",9,9,1],["SE","Sweden","46",9,9,1],["NO","Norway","47",8,8,0],["DK","Denmark","45",8,8,0],["TR","Türkiye","90",10,10,1],["SA","Saudi Arabia","966",9,9,1],["AE","United Arab Emirates","971",9,9,1],["QA","Qatar","974",8,8,0],["KW","Kuwait","965",8,8,0],["JO","Jordan","962",9,9,1],["LB","Lebanon","961",7,8,1],["IQ","Iraq","964",10,10,1],["IR","Iran","98",10,10,1],["IN","India","91",10,10,1],["PK","Pakistan","92",10,10,1],["BD","Bangladesh","880",10,10,1],["CN","China","86",11,11,0],["JP","Japan","81",10,10,1],["KR","South Korea","82",9,10,1],["MY","Malaysia","60",9,10,1],["SG","Singapore","65",8,8,0],["ID","Indonesia","62",9,12,1],["PH","Philippines","63",10,10,1],["US","United States","1",10,10,0],["CA","Canada","1",10,10,0],["BR","Brazil","55",10,11,1],["MX","Mexico","52",10,10,0],["AR","Argentina","54",10,10,1],["AU","Australia","61",9,9,1],["NZ","New Zealand","64",8,10,1]];
const OTP_TTL = 300000, OTP_RESEND_MS = 60000, OTP_MAX_ATTEMPTS = 5, OTP_PER_PHONE_HOUR = 5, OTP_PER_IP_HOUR = 15;
const SESSION_COOKIE = '__Host-sl', COOKIE_MAX = 180 * 86400;                         // login stays for 180 days since last use
const SESSION_IDLE_MS = COOKIE_MAX * 1000;
function normalizePhone(countryIso, raw) {                                           // -> { e164, iso } or { error }
  let s = String(raw == null ? '' : raw).trim();
  if (!/^[+\d\s().-]{4,25}$/.test(s)) return { error: 'Enter a valid phone number' };
  const plus = s.startsWith('+') || s.startsWith('00');
  let digits = s.replace(/\D/g, ''); if (s.startsWith('00')) digits = digits.slice(2);
  let c;
  if (plus) { c = COUNTRIES.filter(x => digits.startsWith(x[2])).sort((a, b) => b[2].length - a[2].length)[0]; if (!c) return { error: 'This country code is not supported yet' }; digits = digits.slice(c[2].length); if (c[2] === '1') c = COUNTRIES.find(x => x[0] === (countryIso === 'CA' ? 'CA' : 'US')); }
  else { c = COUNTRIES.find(x => x[0] === String(countryIso || '').toUpperCase()); if (!c) return { error: 'Choose your country' }; if (digits.startsWith(c[2]) && digits.length > c[4] + (c[5] ? 1 : 0)) digits = digits.slice(c[2].length); }
  if (c[5] && digits.startsWith('0')) digits = digits.slice(1);
  if (digits.length < c[3] || digits.length > c[4] || digits[0] === '0') return { error: `Enter a valid ${c[1]} phone number` };
  if (c[0] === 'NG' && !/^[789][01]\d{8}$/.test(digits)) return { error: 'Enter a valid Nigerian mobile number (e.g. 0803 123 4567)' };
  if (c[2].length + digits.length > 15) return { error: 'Enter a valid phone number' };
  return { e164: '+' + c[2] + digits, iso: c[0] };
}
const maskPhone = e => e.length > 7 ? e.slice(0, e.length - 7) + ' ••• ' + e.slice(-3) : e;
const smsProvider = env => env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && (env.TWILIO_FROM || env.TWILIO_MESSAGING_SERVICE_SID) ? 'twilio' : env.TERMII_API_KEY && env.TERMII_BASE_URL && env.TERMII_SENDER_ID ? 'termii' : null;
async function sendSms(env, e164, text) {                                            // real provider only; returns true only when the provider accepted the message
  const prov = smsProvider(env);
  try {
    if (prov === 'twilio') {
      const f = new URLSearchParams({ To: e164, Body: text }); if (env.TWILIO_MESSAGING_SERVICE_SID) f.set('MessagingServiceSid', env.TWILIO_MESSAGING_SERVICE_SID); else f.set('From', env.TWILIO_FROM);
      const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(env.TWILIO_ACCOUNT_SID)}/Messages.json`, { method: 'POST', headers: { authorization: 'Basic ' + btoa(env.TWILIO_ACCOUNT_SID + ':' + env.TWILIO_AUTH_TOKEN), 'content-type': 'application/x-www-form-urlencoded' }, body: f });
      return r.ok;
    }
    if (prov === 'termii') {
      const r = await fetch(String(env.TERMII_BASE_URL).replace(/\/+$/, '') + '/api/sms/send', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ api_key: env.TERMII_API_KEY, to: e164.slice(1), from: env.TERMII_SENDER_ID, sms: text, type: 'plain', channel: env.TERMII_CHANNEL || 'dnd' }) });
      if (!r.ok) return false; const d = await r.json().catch(() => null); return !!d && (d.code === 'ok' || /sent/i.test(String(d.message || '')));
    }
  } catch {}
  return false;
}
const otpHash = async (env, salt, phone, code) => {                                   // HMAC keyed with the OTP_PEPPER secret: a stolen database cannot be brute-forced offline
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.OTP_PEPPER || 'sunlight-otp-v1'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(`${salt}|${phone}|${code}`)));
};
const newCode = () => { const b = new Uint32Array(1); do crypto.getRandomValues(b); while (b[0] >= 4294000000); return String(b[0] % 1000000).padStart(6, '0'); };   // uniform, 6 digits
const cookieOf = req => { const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)__Host-sl=([a-f0-9]{16,128})/); return m ? m[1] : ''; };
const sessionCookie = (tok, maxAge) => `${SESSION_COOKIE}=${tok}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;

const ipHashOf = async req => (await sha('ip|' + (req.headers.get('cf-connecting-ip') || 'unknown'))).slice(0, 24);
const phoneBody = body => normalizePhone(body.country, body.phone);
async function otpIssue(env, req, now, phone, purpose, userId) {                      // returns a Response (success or error)
  const db = env.DB;
  if (!smsProvider(env)) return json({ error: 'SMS sign-in is not set up on this server yet. The owner must add an SMS provider (see README).', code: 'SMS_NOT_CONFIGURED' }, 503);
  const ip = await ipHashOf(req);
  const last = await db.prepare('SELECT created_at FROM otp_requests WHERE phone=? AND purpose=? AND consumed_at IS NOT -1 ORDER BY id DESC LIMIT 1').bind(phone, purpose).first();
  if (last && now - last.created_at < OTP_RESEND_MS) { const w = Math.ceil((OTP_RESEND_MS - (now - last.created_at)) / 1000); return json({ error: `Please wait ${w}s before requesting another code`, retry_after: w }, 429); }
  const hp = await db.prepare('SELECT COUNT(*) n FROM otp_requests WHERE phone=? AND created_at>?').bind(phone, now - 3600000).first();
  if (hp.n >= OTP_PER_PHONE_HOUR) return json({ error: 'Too many codes requested for this number. Try again in an hour.', retry_after: 3600 }, 429);
  const hi = await db.prepare('SELECT COUNT(*) n FROM otp_requests WHERE ip_hash=? AND created_at>?').bind(ip, now - 3600000).first();
  if (hi.n >= OTP_PER_IP_HOUR) return json({ error: 'Too many requests. Try again later.', retry_after: 3600 }, 429);
  const code = newCode(), salt = rand(8);
  const ins = await db.prepare('INSERT INTO otp_requests(phone,purpose,user_id,code_hash,salt,attempts,expires_at,created_at,ip_hash) VALUES(?,?,?,?,?,0,?,?,?)').bind(phone, purpose, userId || null, await otpHash(env, salt, phone, code), salt, now + OTP_TTL, now, ip).run();
  await db.prepare('UPDATE otp_requests SET consumed_at=?1 WHERE phone=?2 AND purpose=?3 AND id<?4 AND consumed_at IS NULL').bind(now, phone, purpose, ins.meta.last_row_id).run();   // older codes die when a new one is issued
  const sent = await sendSms(env, phone, `Your SUNLIGHT code is ${code}. It expires in 5 minutes. Do not share it with anyone.`);
  if (!sent) { await db.prepare('UPDATE otp_requests SET consumed_at=-1 WHERE id=?').bind(ins.meta.last_row_id).run(); return json({ error: 'The SMS could not be sent. Check the number and try again.', code: 'SMS_SEND_FAILED' }, 502); }
  if (Math.random() < 0.05) await db.batch([db.prepare('DELETE FROM otp_requests WHERE created_at<?').bind(now - 86400000), db.prepare('DELETE FROM auth_fails WHERE at<?').bind(now - 86400000), db.prepare('DELETE FROM signup_tickets WHERE expires_at<?').bind(now - 86400000), db.prepare('DELETE FROM sessions WHERE MAX(last_used,created_at)<?').bind(now - SESSION_IDLE_MS)]).catch(() => {});
  return json({ ok: true, masked: maskPhone(phone), resend_in: OTP_RESEND_MS / 1000, expires_in: OTP_TTL / 1000 });
}
async function otpCheck(env, req, now, phone, purpose, userId, codeRaw) {            // -> { ok:true } or { res: Response }
  const db = env.DB, ip = await ipHashOf(req), code = String(codeRaw || '').trim();
  const fails = await db.prepare('SELECT COUNT(*) n FROM auth_fails WHERE k=? AND at>?').bind('otp:' + ip, now - 900000).first();
  if (fails.n >= 20) return { res: json({ error: 'Too many wrong attempts. Try again in 15 minutes.' }, 429) };
  if (!/^\d{6}$/.test(code)) return { res: json({ error: 'Enter the 6-digit code' }, 400) };
  const r = await db.prepare('SELECT * FROM otp_requests WHERE phone=? AND purpose=? AND consumed_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1').bind(phone, purpose, now).first();
  if (!r || (userId && r.user_id !== userId)) return { res: json({ error: 'This code has expired or was already used. Request a new code.', code: 'OTP_EXPIRED' }, 400) };
  if (r.attempts >= OTP_MAX_ATTEMPTS) { await db.prepare('UPDATE otp_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL').bind(now, r.id).run(); return { res: json({ error: 'Too many wrong codes. Request a new code.', code: 'OTP_LOCKED' }, 429) }; }
  if (!safeEq(await otpHash(env, r.salt, phone, code), r.code_hash)) {
    await db.batch([db.prepare('UPDATE otp_requests SET attempts=attempts+1 WHERE id=?').bind(r.id), db.prepare('INSERT INTO auth_fails(k,at) VALUES(?,?)').bind('otp:' + ip, now)]);
    const left = OTP_MAX_ATTEMPTS - r.attempts - 1;
    if (left <= 0) await db.prepare('UPDATE otp_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL').bind(now, r.id).run();
    return { res: json({ error: left > 0 ? `Wrong code. ${left} attempt${left === 1 ? '' : 's'} left.` : 'Wrong code. Request a new code.', code: left > 0 ? 'OTP_WRONG' : 'OTP_LOCKED' }, 400) };
  }
  const c = await db.prepare('UPDATE otp_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL').bind(now, r.id).run();   // single use, atomic
  if (!c.meta.changes) return { res: json({ error: 'This code was already used. Request a new code.', code: 'OTP_EXPIRED' }, 400) };
  return { ok: true };
}
const failCount = (db, k, now) => db.prepare('SELECT COUNT(*) n FROM auth_fails WHERE k=? AND at>?').bind(k, now - 900000).first().then(r => r.n);

async function startSession(db, user, now, out, req, extra = {}) {
  const token = rand(32);                                                              // 256-bit random id; only its SHA-256 hash is stored
  await db.prepare('INSERT INTO sessions(token,user_id,created_at,last_used,ua) VALUES(?,?,?,?,?)').bind(await sha(token), user.id, now, now, String(req.headers.get('user-agent') || '').slice(0, 120)).run();
  out.cookie = sessionCookie(token, COOKIE_MAX);
  return json({ user, ...extra });
}

async function route(req, env, url, out) {
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
    return json({ ok: true, version: APP_VERSION, database: 'connected', sms: !!smsProvider(env), video: !!env.MEDIA, assets: !!env.ASSETS, users: r.n });
  }

  // =============== PHONE + OTP AUTHENTICATION ===============
  const originOk = () => { const o = req.headers.get('origin'); if (o && o !== url.origin) return false; return req.headers.get('sec-fetch-site') !== 'cross-site'; };
  if (post && p.startsWith('auth/') && !originOk()) return json({ error: 'Blocked' }, 403);

  if (p === 'auth/otp/request' && post) {
    const ph = phoneBody(body); if (ph.error) return json({ error: ph.error }, 400);
    return otpIssue(env, req, now, ph.e164, 'login', null);
  }
  if (p === 'auth/otp/verify' && post) {
    const ph = phoneBody(body); if (ph.error) return json({ error: ph.error }, 400);
    const c = await otpCheck(env, req, now, ph.e164, 'login', null, body.code); if (c.res) return c.res;
    const u = await db.prepare('SELECT id,username,name,avatar_key FROM users WHERE phone=?').bind(ph.e164).first();
    if (u) return startSession(db, { id: u.id, username: u.username, name: u.name, avatar: u.avatar_key || null }, now, out, req, { status: 'ok' });
    const t = rand(24);
    await db.prepare('INSERT INTO signup_tickets(hash,phone,expires_at,used) VALUES(?,?,?,0)').bind(await sha(t), ph.e164, now + 900000).run();
    return json({ status: 'new', ticket: t });
  }
  const ticketOf = async t => typeof t === 'string' && /^[a-f0-9]{48}$/.test(t) ? db.prepare('SELECT * FROM signup_tickets WHERE hash=? AND used=0 AND expires_at>?').bind(await sha(t), now).first() : null;
  if (p === 'auth/username-check' && !post) {
    if (!(await ticketOf(url.searchParams.get('ticket')))) return json({ available: false, reason: 'Verification expired. Start again.' });
    const u = String(url.searchParams.get('u') || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return json({ available: false, reason: 'Username: 3–20 letters, numbers or _' });
    if (RESERVED.has(u)) return json({ available: false, reason: 'This username is reserved' });
    const t = await db.prepare('SELECT id FROM users WHERE username=?').bind(u).first();
    return json({ available: !t, reason: t ? 'Username already taken' : '' });
  }
  if (p === 'auth/signup' && post) {
    const username = String(body.username || '').trim().toLowerCase(), name = String(body.name || '').trim();
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return json({ error: 'Username: 3–20 letters, numbers or _' }, 400);
    if (RESERVED.has(username)) return json({ error: 'This username is reserved' }, 400);
    if (!name || name.length > 40) return json({ error: 'Enter your name (max 40 characters)' }, 400);
    const t = await ticketOf(body.ticket); if (!t) return json({ error: 'Your verification expired. Please verify your phone again.', code: 'TICKET_EXPIRED' }, 400);
    const th = t.hash, claim = await db.prepare('UPDATE signup_tickets SET used=1 WHERE hash=? AND used=0').bind(th).run();
    if (!claim.meta.changes) return json({ error: 'Your verification expired. Please verify your phone again.', code: 'TICKET_EXPIRED' }, 400);
    let r;
    try { r = await db.prepare("INSERT INTO users(username,name,pass_hash,salt,phone,phone_verified_at,created_at,last_seen) VALUES(?,?,'','',?,?,?,?)").bind(username, name, t.phone, now, now, now).run(); }
    catch (e) {
      if (/UNIQUE|constraint/i.test(String(e && e.message))) {
        if (/phone/i.test(String(e.message))) return json({ error: 'This number is already registered. Sign in instead.' }, 409);
        await db.prepare('UPDATE signup_tickets SET used=0 WHERE hash=?').bind(th).run();   // let the person pick another username
        return json({ error: 'Username already taken' }, 409);
      }
      throw e;
    }
    return startSession(db, { id: r.meta.last_row_id, username, name, avatar: null }, now, out, req, { status: 'ok' });
  }
  // Existing accounts created before phone sign-in: username + old password, ONLY to get in and link a verified phone. Never works for accounts that already have a phone.
  if (p === 'auth/legacy' && post) {
    if (env.LEGACY_LOGIN === '0') return json({ error: 'Please sign in with your phone number' }, 403);
    const ident = String(body.username || '').trim().toLowerCase().slice(0, 120), pw = String(body.password || '').slice(0, 200), ip = await ipHashOf(req);
    if (!ident || !pw) return json({ error: 'Enter your username and old password' }, 400);
    if (await failCount(db, 'leg:' + ip, now) >= 10 || await failCount(db, 'legu:' + ident, now) >= 10) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
    const u = await db.prepare('SELECT id,username,name,avatar_key,pass_hash,salt,phone FROM users WHERE username=?1 OR email=?1').bind(ident).first();
    const ok = u && u.pass_hash && safeEq(await hashPw(pw, u.salt), u.pass_hash);
    if (!ok) { await db.batch([db.prepare('INSERT INTO auth_fails(k,at) VALUES(?,?)').bind('leg:' + ip, now), db.prepare('INSERT INTO auth_fails(k,at) VALUES(?,?)').bind('legu:' + ident, now)]); return json({ error: 'Incorrect username or password' }, 401); }
    if (u.phone) return json({ error: 'This account now uses phone sign-in. Enter your phone number instead.', code: 'USE_PHONE' }, 403);
    return startSession(db, { id: u.id, username: u.username, name: u.name, avatar: u.avatar_key || null }, now, out, req, { status: 'ok', needs_phone: true });
  }
  // Old browser-stored token (from before this update) is exchanged once for a secure cookie session and then destroyed.
  if (p === 'auth/adopt' && post) {
    const old = (req.headers.get('authorization') || '').replace('Bearer ', '');
    const u = /^[a-f0-9]{16,128}$/.test(old) ? await db.prepare('SELECT u.id,u.username,u.name,u.avatar_key,u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created_at>?').bind(old, now - SESSION_MS).first() : null;
    if (!u) return json({ error: 'Please sign in' }, 401);
    await db.prepare('DELETE FROM sessions WHERE token=?').bind(old).run();
    return startSession(db, { id: u.id, username: u.username, name: u.name, avatar: u.avatar_key || null }, now, out, req, { status: 'ok', needs_phone: !u.phone });
  }

  // ---- authenticated routes (secure cookie only) ----
  const ctok = cookieOf(req), sid = ctok ? await sha(ctok) : '';
  if (post && ctok && !originOk()) return json({ error: 'Blocked' }, 403);          // CSRF guard for cookie-authenticated writes
  if (p === 'logout' && post) {
    if (sid) await db.prepare('DELETE FROM sessions WHERE token=?').bind(sid).run();
    out.cookie = sessionCookie('', 0);
    return json({ ok: true });
  }
  const me = sid ? await db.prepare('SELECT u.id,u.username,u.name,u.avatar_key avatar,u.last_seen,s.last_used,s.created_at sc FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND MAX(s.last_used,s.created_at)>?').bind(sid, now - SESSION_IDLE_MS).first() : null;
  if (!me) { if (ctok) out.cookie = sessionCookie('', 0); return json({ error: 'Please log in' }, 401); }
  if (now - me.last_used > 12 * 3600000) { await db.prepare('UPDATE sessions SET last_used=? WHERE token=?').bind(now, sid).run(); out.cookie = sessionCookie(ctok, COOKIE_MAX); }   // sliding: stays logged in while you keep using it
  if (now - me.last_seen > 10000) await db.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now, me.id).run(); // throttled: saves D1 writes
  delete me.last_seen; delete me.last_used; delete me.sc;
  const tok = sid;

  if (p === 'me') { const u = await db.prepare('SELECT phone FROM users WHERE id=?').bind(me.id).first(); return json({ user: me, has_phone: !!(u && u.phone) }); }

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
    let target;                                               // private chat: peer id; group chat: -group id (each user has their OWN row, so one person's wallpaper never changes another's)
    if (body.group != null) { const gid = Number(body.group); const mem = Number.isInteger(gid) && gid > 0 ? await db.prepare('SELECT 1 ok FROM group_members WHERE group_id=? AND user_id=?').bind(gid, me.id).first() : null; if (!mem) return json({ error: 'Group not found' }, 404); target = -gid; }
    else { const peer = await peerOf(body.with); if (!peer) return json({ error: 'User not found' }, 404); target = peer.id; }
    let theme = null;
    if (body.theme != null) {                                 // validated: fixed lists, own image key, bounded dim: nothing else can be stored
      const t = body.theme, bg = t.bg == null ? null : String(t.bg), c = t.color == null ? null : String(t.color);
      if ((bg !== null && !THEME_BG.includes(bg)) || (c !== null && !THEME_COLOR.includes(c))) return json({ error: 'Unknown theme' }, 400);
      let wp = null, dim = 35;
      if (t.wp != null) {
        wp = String(t.wp);
        if (!MEDIA_KEY.test(wp) || !wp.startsWith('u' + me.id + '/')) return json({ error: 'Invalid wallpaper' }, 400);          // only YOUR OWN uploads
        const m = await db.prepare('SELECT type FROM media WHERE key=? AND owner_id=?').bind(wp, me.id).first();
        if (!m || !/^image\/(jpeg|png|webp)$/.test(m.type)) return json({ error: 'Invalid wallpaper' }, 400);
        if (t.dim != null) { dim = Number(t.dim); if (!Number.isInteger(dim) || dim < 0 || dim > 80) return json({ error: 'Invalid dark overlay' }, 400); }
      }
      theme = bg === null && c === null && wp === null ? null : JSON.stringify({ bg, color: c, ...(wp ? { wp, dim } : {}) });
    }
    await db.prepare('INSERT INTO chat_prefs(user_id,peer_id,theme) VALUES(?1,?2,?3) ON CONFLICT(user_id,peer_id) DO UPDATE SET theme=?3').bind(me.id, target, theme).run();
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

  // =============== SHARED HELPERS: uploads claimed by group messages / channel posts / pictures ===============
  const EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
  const refUsed = async key => !!(await db.prepare(`SELECT 1 ok WHERE ?1 IN ${REFS}`).bind(key).first());
  const claimMedia = async (key, want) => {                  // want: 'image' | 'voice' | 'video'. Only YOUR OWN, unused, correctly typed upload can be attached
    key = String(key || '');
    if (!MEDIA_KEY.test(key) || !key.startsWith('u' + me.id + '/')) return { err: 'Invalid media' };
    const up = await db.prepare('SELECT type,size FROM media WHERE key=? AND owner_id=?').bind(key, me.id).first();
    if (!up) return { err: 'Upload not found. Please try again.' };
    if (!up.type.startsWith(want === 'image' ? 'image/' : want === 'video' ? 'video/' : 'audio/')) return { err: 'Media type does not match' };
    if (await refUsed(key)) return { err: 'Media already used' };
    return { key, mtype: up.type, msize: up.size };
  };
  const cleanName = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
  const GROUP_MAX = 100;

  // =============== GROUPS ===============
  const gRole = async gid => { const r = await db.prepare('SELECT role,joined_at FROM group_members WHERE group_id=? AND user_id=?').bind(gid, me.id).first(); return r || null; };
  const isAdminRole = r => r === 'owner' || r === 'admin';
  const groupDrop = async gid => {                            // remove a whole group, its messages and its uploads
    const { results: keys } = await db.prepare('SELECT media_key k FROM group_messages WHERE group_id=?1 AND media_key IS NOT NULL UNION SELECT avatar_key FROM groups WHERE id=?1 AND avatar_key IS NOT NULL').bind(gid).all();
    for (const k of keys) await dropAny(k.k);
    await db.batch(['DELETE FROM group_reactions WHERE message_id IN (SELECT id FROM group_messages WHERE group_id=?1)', 'DELETE FROM group_messages WHERE group_id=?1', 'DELETE FROM group_reads WHERE group_id=?1', 'DELETE FROM group_members WHERE group_id=?1', 'DELETE FROM chat_prefs WHERE peer_id=-?1', 'DELETE FROM groups WHERE id=?1'].map(q => db.prepare(q).bind(gid)));
  };
  const groupLeave = async (gid, uid) => {                    // owner leaving hands the group to the oldest admin, then the oldest member; the last person out deletes it
    const m = await db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').bind(gid, uid).first(); if (!m) return;
    await db.prepare('DELETE FROM group_members WHERE group_id=? AND user_id=?').bind(gid, uid).run();
    await db.prepare('DELETE FROM group_reads WHERE group_id=? AND user_id=?').bind(gid, uid).run();
    await db.prepare('DELETE FROM chat_prefs WHERE user_id=? AND peer_id=?').bind(uid, -gid).run();
    const next = await db.prepare("SELECT user_id FROM group_members WHERE group_id=? ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, joined_at, user_id LIMIT 1").bind(gid).first();
    if (!next) return groupDrop(gid);
    if (m.role === 'owner') await db.prepare("UPDATE group_members SET role='owner' WHERE group_id=? AND user_id=?").bind(gid, next.user_id).run();
  };
  const groupView = async (gid, role) => {
    const g = await db.prepare('SELECT id,name,description,avatar_key,created_by,created_at FROM groups WHERE id=?').bind(gid).first();
    const n = await db.prepare('SELECT COUNT(*) n FROM group_members WHERE group_id=?').bind(gid).first();
    return { id: g.id, name: g.name, description: g.description, avatar: g.avatar_key || null, created_at: g.created_at, members: n.n, role };
  };
  const gmsgShape = (m, rx, mineId) => ({ id: m.id, sender_id: m.sender_id, sender: { id: m.sender_id, name: m.sname || 'Former member', username: m.suser || null, avatar: m.sav || null }, body: m.deleted_at ? '' : m.body, type: m.type, media_key: m.deleted_at ? null : m.media_key, media_type: m.media_type, media_size: m.media_size, duration: m.duration, reply_to: m.reply_to, created_at: m.created_at, deleted_at: m.deleted_at, reactions: rx });

  if (p === 'groups' && !post) {
    const { results } = await db.prepare(`
      SELECT g.id,g.name,g.description,g.avatar_key,gm.role,
        (SELECT COUNT(*) FROM group_members x WHERE x.group_id=g.id) members,
        m.id last_id,m.type last_type,m.body last_body,m.created_at last_at,m.sender_id last_sender,m.deleted_at last_deleted,u.name last_name,
        (SELECT COUNT(*) FROM group_messages z WHERE z.group_id=g.id AND z.id>COALESCE((SELECT last_id FROM group_reads r WHERE r.group_id=g.id AND r.user_id=?1),0) AND z.sender_id!=?1 AND z.created_at>=gm.joined_at AND z.deleted_at IS NULL) unread
      FROM group_members gm JOIN groups g ON g.id=gm.group_id
      LEFT JOIN group_messages m ON m.id=(SELECT MAX(id) FROM group_messages WHERE group_id=g.id AND created_at>=gm.joined_at)
      LEFT JOIN users u ON u.id=m.sender_id
      WHERE gm.user_id=?1 ORDER BY COALESCE(m.created_at,g.created_at) DESC LIMIT 200`).bind(me.id).all();
    return json({ groups: results.map(g => ({ id: g.id, name: g.name, description: g.description, avatar: g.avatar_key || null, role: g.role, members: g.members, unread: g.unread, last: g.last_id ? { id: g.last_id, type: g.last_type, body: g.last_deleted ? '' : g.last_body, at: g.last_at, sender_id: g.last_sender, sender: g.last_name || '', deleted: !!g.last_deleted } : null })) });
  }
  if (p === 'groups' && post) {
    const name = cleanName(body.name, 40), desc = cleanName(body.description, 200);
    if (name.length < 1) return json({ error: 'Enter a group name (max 40 characters)' }, 400);
    const ids = [...new Set((Array.isArray(body.members) ? body.members : []).map(Number).filter(n => Number.isInteger(n) && n > 0 && n !== me.id))];
    if (ids.length > GROUP_MAX - 1) return json({ error: `A group can have up to ${GROUP_MAX} members` }, 400);
    let avatar = null;
    if (body.avatar_key) { const c = await claimMedia(body.avatar_key, 'image'); if (c.err) return json({ error: c.err }, 400); if (c.msize > 250000) return json({ error: 'Group picture is too large' }, 413); avatar = c.key; }
    const ok = [];                                           // only people saved in MY contacts, who have not blocked me / are not blocked by me
    for (const id of ids) { if (await db.prepare('SELECT 1 ok FROM contacts WHERE owner_id=? AND contact_id=?').bind(me.id, id).first() && !(await eitherBlocked(me.id, id))) ok.push(id); }
    const r = await db.prepare('INSERT INTO groups(name,description,avatar_key,created_by,created_at) VALUES(?,?,?,?,?)').bind(name, desc, avatar, me.id, now).run();
    const gid = r.meta.last_row_id;
    await db.batch([db.prepare("INSERT INTO group_members(group_id,user_id,role,joined_at,added_by) VALUES(?,?,'owner',?,?)").bind(gid, me.id, now, me.id), ...ok.map(id => db.prepare("INSERT INTO group_members(group_id,user_id,role,joined_at,added_by) VALUES(?,?,'member',?,?)").bind(gid, id, now, me.id))]);
    return json({ group: await groupView(gid, 'owner'), skipped: ids.length - ok.length });
  }
  if (p === 'groups/info' && !post) {
    const gid = Number(url.searchParams.get('id')), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    const { results } = await db.prepare("SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,gm.role,gm.joined_at FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.name").bind(gid).all();
    return json({ group: await groupView(gid, mine.role), members: results.map(u => ({ ...publicUser(u, now), role: u.role, is_contact: undefined })) });
  }
  if (p === 'groups/update' && post) {
    const gid = Number(body.id), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    if (!isAdminRole(mine.role)) return json({ error: 'Only admins can edit the group' }, 403);
    const g = await db.prepare('SELECT name,description,avatar_key FROM groups WHERE id=?').bind(gid).first();
    let name = g.name, desc = g.description, avatar = g.avatar_key;
    if (body.name !== undefined) { name = cleanName(body.name, 40); if (!name) return json({ error: 'Enter a group name (max 40 characters)' }, 400); }
    if (body.description !== undefined) desc = cleanName(body.description, 200);
    if (body.avatar_key) { const c = await claimMedia(body.avatar_key, 'image'); if (c.err) return json({ error: c.err }, 400); if (c.msize > 250000) return json({ error: 'Group picture is too large' }, 413); avatar = c.key; }
    else if (body.remove_avatar) avatar = null;
    await db.prepare('UPDATE groups SET name=?,description=?,avatar_key=? WHERE id=?').bind(name, desc, avatar, gid).run();
    if (g.avatar_key && g.avatar_key !== avatar) await dropAny(g.avatar_key);
    return json({ group: await groupView(gid, mine.role) });
  }
  if (p === 'groups/members/add' && post) {
    const gid = Number(body.id), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    if (!isAdminRole(mine.role)) return json({ error: 'Only admins can add members' }, 403);
    const ids = [...new Set((Array.isArray(body.user_ids) ? body.user_ids : []).map(Number).filter(n => Number.isInteger(n) && n > 0))];
    let count = (await db.prepare('SELECT COUNT(*) n FROM group_members WHERE group_id=?').bind(gid).first()).n, added = 0;
    for (const id of ids) {
      if (count >= GROUP_MAX) return json({ error: `A group can have up to ${GROUP_MAX} members`, added }, 400);
      if (!(await db.prepare('SELECT 1 ok FROM contacts WHERE owner_id=? AND contact_id=?').bind(me.id, id).first()) || await eitherBlocked(me.id, id)) continue;
      const r = await db.prepare("INSERT OR IGNORE INTO group_members(group_id,user_id,role,joined_at,added_by) VALUES(?,?,'member',?,?)").bind(gid, id, now, me.id).run();
      if (r.meta.changes) { added++; count++; }
    }
    return json({ ok: true, added, group: await groupView(gid, mine.role) });
  }
  if (p === 'groups/members/remove' && post) {
    const gid = Number(body.id), uid = Number(body.user_id), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    const t = await db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').bind(gid, uid).first();
    if (!t || uid === me.id) return json({ error: 'Member not found' }, 404);
    if (!isAdminRole(mine.role)) return json({ error: 'Only admins can remove members' }, 403);
    if (t.role === 'owner' || (t.role === 'admin' && mine.role !== 'owner')) return json({ error: t.role === 'owner' ? 'The group owner cannot be removed' : 'Only the owner can remove an admin' }, 403);
    await groupLeave(gid, uid);
    return json({ ok: true });
  }
  if (p === 'groups/members/role' && post) {
    const gid = Number(body.id), uid = Number(body.user_id), role = body.role, mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    if (role !== 'admin' && role !== 'member') return json({ error: 'Invalid role' }, 400);
    const t = await db.prepare('SELECT role FROM group_members WHERE group_id=? AND user_id=?').bind(gid, uid).first();
    if (!t || uid === me.id) return json({ error: 'Member not found' }, 404);
    if (t.role === 'owner') return json({ error: "The owner's role cannot be changed" }, 403);
    if (role === 'admin' && !isAdminRole(mine.role)) return json({ error: 'Only admins can promote members' }, 403);
    if (role === 'member' && mine.role !== 'owner') return json({ error: 'Only the owner can demote an admin' }, 403);
    await db.prepare('UPDATE group_members SET role=? WHERE group_id=? AND user_id=?').bind(role, gid, uid).run();
    return json({ ok: true, role });
  }
  if (p === 'groups/leave' && post) {
    const gid = Number(body.id); if (!Number.isInteger(gid) || !(await gRole(gid))) return json({ error: 'Group not found' }, 404);
    await groupLeave(gid, me.id); return json({ ok: true });
  }
  if (p === 'groups/delete' && post) {
    const gid = Number(body.id), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    if (mine.role !== 'owner') return json({ error: 'Only the owner can delete the group' }, 403);
    await groupDrop(gid); return json({ ok: true });
  }
  if (p === 'groups/messages' && !post) {
    const gid = Number(url.searchParams.get('id')), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    const { results } = await db.prepare(`SELECT * FROM (SELECT m.*,u.name sname,u.username suser,u.avatar_key sav FROM group_messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.group_id=?1 AND m.created_at>=?2 ORDER BY m.id DESC LIMIT 200) ORDER BY id`).bind(gid, mine.joined_at).all();
    const ids = results.map(m => m.id), rx = new Map();
    if (ids.length) { const { results: rr } = await db.prepare(`SELECT message_id,emoji,user_id FROM group_reactions WHERE message_id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all(); for (const r of rr) { const a = rx.get(r.message_id) || new Map(); const e = a.get(r.emoji) || { emoji: r.emoji, count: 0, mine: false }; e.count++; if (r.user_id === me.id) e.mine = true; a.set(r.emoji, e); rx.set(r.message_id, a); } }
    const last = ids.length ? ids[ids.length - 1] : 0;
    if (last) await db.prepare('INSERT INTO group_reads(group_id,user_id,last_id) VALUES(?1,?2,?3) ON CONFLICT(group_id,user_id) DO UPDATE SET last_id=MAX(last_id,?3)').bind(gid, me.id, last).run();
    const gp = await db.prepare('SELECT theme FROM chat_prefs WHERE user_id=? AND peer_id=?').bind(me.id, -gid).first();
    let gtheme = null; if (gp && gp.theme) try { gtheme = JSON.parse(gp.theme); } catch {}
    return json({ messages: results.map(m => gmsgShape(m, rx.has(m.id) ? [...rx.get(m.id).values()] : [])), group: await groupView(gid, mine.role), theme: gtheme });
  }
  if (p === 'groups/send' && post) {
    const gid = Number(body.id), mine = Number.isInteger(gid) ? await gRole(gid) : null;
    if (!mine) return json({ error: 'Group not found' }, 404);
    const text = String(body.body || '').trim(), type = ['text', 'image', 'voice', 'video'].includes(body.type) ? body.type : 'text';
    if (text.length > 2000 || (type === 'text' && !text)) return json({ error: 'Message must be 1–2000 characters' }, 400);
    let key = null, mtype = null, msize = null, dur = null, replyTo = null;
    if (type !== 'text') { const c = await claimMedia(body.media_key, type); if (c.err) return json({ error: c.err }, 400); key = c.key; mtype = c.mtype; msize = c.msize; dur = type === 'voice' || type === 'video' ? Math.min(3600, Math.max(0, Math.round(Number(body.duration) || 0))) : null; }
    if (body.reply_to != null) { const rid = Number(body.reply_to); if (Number.isInteger(rid) && await db.prepare('SELECT id FROM group_messages WHERE id=? AND group_id=?').bind(rid, gid).first()) replyTo = rid; }
    const recent = await db.prepare('SELECT COUNT(*) n FROM group_messages WHERE sender_id=? AND created_at>?').bind(me.id, now - 10000).first();
    if (recent.n >= 20) return json({ error: 'You are sending too fast. Slow down.' }, 429);
    const r = await db.prepare('INSERT INTO group_messages(group_id,sender_id,body,type,media_key,media_type,media_size,duration,reply_to,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(gid, me.id, text, type, key, mtype, msize, dur, replyTo, now).run();
    await db.prepare('INSERT INTO group_reads(group_id,user_id,last_id) VALUES(?1,?2,?3) ON CONFLICT(group_id,user_id) DO UPDATE SET last_id=MAX(last_id,?3)').bind(gid, me.id, r.meta.last_row_id).run();
    return json({ id: r.meta.last_row_id, created_at: now });
  }
  if (p === 'groups/messages/delete' && post) {
    const mid = Number(body.id), m = Number.isInteger(mid) ? await db.prepare('SELECT id,group_id,sender_id,media_key FROM group_messages WHERE id=? AND deleted_at IS NULL').bind(mid).first() : null;
    const mine = m ? await gRole(m.group_id) : null;
    if (!m || !mine) return json({ error: 'Message not found' }, 404);
    if (m.sender_id !== me.id && !isAdminRole(mine.role)) return json({ error: 'You can only delete your own messages' }, 403);
    await db.prepare("UPDATE group_messages SET deleted_at=?, body='', media_key=NULL WHERE id=?").bind(now, mid).run();
    await db.prepare('DELETE FROM group_reactions WHERE message_id=?').bind(mid).run();
    if (m.media_key) await dropAny(m.media_key);
    return json({ ok: true });
  }
  if (p === 'groups/react' && post) {
    const mid = Number(body.message_id), m = Number.isInteger(mid) ? await db.prepare('SELECT id,group_id FROM group_messages WHERE id=? AND deleted_at IS NULL').bind(mid).first() : null;
    if (!m || !(await gRole(m.group_id))) return json({ error: 'Message not found' }, 404);
    const emoji = body.emoji;
    if (emoji === null || emoji === '') { await db.prepare('DELETE FROM group_reactions WHERE message_id=? AND user_id=?').bind(mid, me.id).run(); return json({ ok: true, emoji: null }); }
    if (!EMOJIS.includes(emoji)) return json({ error: 'Reaction not allowed' }, 400);
    const cur = await db.prepare('SELECT emoji FROM group_reactions WHERE message_id=? AND user_id=?').bind(mid, me.id).first();
    if (cur && cur.emoji === emoji) { await db.prepare('DELETE FROM group_reactions WHERE message_id=? AND user_id=?').bind(mid, me.id).run(); return json({ ok: true, emoji: null }); }   // tap the same one again to remove
    await db.prepare('INSERT INTO group_reactions(message_id,user_id,emoji,created_at) VALUES(?1,?2,?3,?4) ON CONFLICT(message_id,user_id) DO UPDATE SET emoji=?3,created_at=?4').bind(mid, me.id, emoji, now).run();
    return json({ ok: true, emoji });
  }

  // =============== CHANNELS ===============
  const cRole = async cid => { const r = await db.prepare('SELECT role,joined_at FROM channel_members WHERE channel_id=? AND user_id=?').bind(cid, me.id).first(); return r ? r.role : null; };
  const chanDrop = async cid => {
    const { results: keys } = await db.prepare('SELECT media_key k FROM channel_posts WHERE channel_id=?1 AND media_key IS NOT NULL UNION SELECT avatar_key FROM channels WHERE id=?1 AND avatar_key IS NOT NULL').bind(cid).all();
    for (const k of keys) await dropAny(k.k);
    await db.batch(['DELETE FROM channel_comments WHERE post_id IN (SELECT id FROM channel_posts WHERE channel_id=?1)', 'DELETE FROM channel_reactions WHERE post_id IN (SELECT id FROM channel_posts WHERE channel_id=?1)', 'DELETE FROM channel_posts WHERE channel_id=?1', 'DELETE FROM channel_members WHERE channel_id=?1', 'DELETE FROM channels WHERE id=?1'].map(q => db.prepare(q).bind(cid)));
  };
  // a person may READ a channel if it is public, or if they are a member (private channels: members only)
  const chanAccess = async cid => {
    if (!Number.isInteger(cid)) return null;
    const c = await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first(); if (!c) return null;
    const role = await cRole(cid);
    if (c.visibility === 'private' && !role) return null;
    return { c, role };
  };
  const chanView = async (c, role) => {
    const n = await db.prepare('SELECT COUNT(*) n FROM channel_members WHERE channel_id=?').bind(c.id).first();
    const own = c.owner_id === me.id ? null : await db.prepare('SELECT name FROM users WHERE id=?').bind(c.owner_id).first();
    return { id: c.id, name: c.name, description: c.description, avatar: c.avatar_key || null, visibility: c.visibility, comments_on: !!c.comments_on, subscribers: n.n, role: role || null, subscribed: !!role, created_at: c.created_at, owner: own ? own.name : 'You', invite_code: role === 'owner' || role === 'admin' ? (c.visibility === 'private' ? c.invite_code : null) : null };
  };
  const postShape = (m, rx) => { const total = rx.reduce((a, r) => a + r.count, 0); return { id: m.id, channel_id: m.channel_id, author: { id: m.author_id, name: m.aname || 'Former member' }, author_id: m.author_id, body: m.deleted_at ? '' : m.body, type: m.type, media_key: m.deleted_at ? null : m.media_key, media_type: m.media_type, duration: m.duration, created_at: m.created_at, edited_at: m.edited_at, deleted_at: m.deleted_at, reactions: rx, likes: total, comments: m.ccount || 0 }; };

  if (p === 'channels' && !post) {                           // channels I subscribe to or manage
    const { results } = await db.prepare(`
      SELECT c.id,c.name,c.description,c.avatar_key,c.visibility,cm.role,cm.last_seen_post,
        (SELECT COUNT(*) FROM channel_members x WHERE x.channel_id=c.id) subs,
        p.id last_id,p.type last_type,p.body last_body,p.created_at last_at,
        (SELECT COUNT(*) FROM channel_posts z WHERE z.channel_id=c.id AND z.id>cm.last_seen_post AND z.deleted_at IS NULL AND z.author_id!=?1) unread
      FROM channel_members cm JOIN channels c ON c.id=cm.channel_id
      LEFT JOIN channel_posts p ON p.id=(SELECT MAX(id) FROM channel_posts WHERE channel_id=c.id AND deleted_at IS NULL)
      WHERE cm.user_id=?1 ORDER BY COALESCE(p.created_at,c.created_at) DESC LIMIT 200`).bind(me.id).all();
    return json({ channels: results.map(c => ({ id: c.id, name: c.name, description: c.description, avatar: c.avatar_key || null, visibility: c.visibility, role: c.role, subscribers: c.subs, unread: c.unread, last: c.last_id ? { id: c.last_id, type: c.last_type, body: c.last_body, at: c.last_at } : null })) });
  }
  if (p === 'channels/discover' && !post) {                  // PUBLIC channels only; private ones are never listed
    const q = String(url.searchParams.get('q') || '').trim().slice(0, 40), like = '%' + likeEsc(q.toLowerCase()) + '%';
    const { results } = await db.prepare(`SELECT c.id,c.name,c.description,c.avatar_key,(SELECT COUNT(*) FROM channel_members x WHERE x.channel_id=c.id) subs,(SELECT role FROM channel_members m WHERE m.channel_id=c.id AND m.user_id=?1) role
      FROM channels c WHERE c.visibility='public' AND (?2='' OR LOWER(c.name) LIKE ?3 ESCAPE '\\' OR LOWER(c.description) LIKE ?3 ESCAPE '\\') ORDER BY subs DESC, c.id DESC LIMIT 50`).bind(me.id, q, like).all();
    return json({ channels: results.map(c => ({ id: c.id, name: c.name, description: c.description, avatar: c.avatar_key || null, subscribers: c.subs, subscribed: !!c.role, role: c.role || null })) });
  }
  if (p === 'channels' && post) {
    const name = cleanName(body.name, 40), desc = cleanName(body.description, 300), vis = body.visibility === 'private' ? 'private' : 'public';
    if (!name) return json({ error: 'Enter a channel name (max 40 characters)' }, 400);
    const mineCount = await db.prepare("SELECT COUNT(*) n FROM channels WHERE owner_id=?").bind(me.id).first();
    if (mineCount.n >= 20) return json({ error: 'You can own up to 20 channels' }, 400);
    let avatar = null;
    if (body.avatar_key) { const c = await claimMedia(body.avatar_key, 'image'); if (c.err) return json({ error: c.err }, 400); if (c.msize > 250000) return json({ error: 'Channel picture is too large' }, 413); avatar = c.key; }
    const code = rand(10);
    const r = await db.prepare('INSERT INTO channels(name,description,avatar_key,owner_id,visibility,comments_on,invite_code,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(name, desc, avatar, me.id, vis, body.comments_on === false ? 0 : 1, code, now).run();
    const cid = r.meta.last_row_id;
    await db.prepare("INSERT INTO channel_members(channel_id,user_id,role,joined_at,last_seen_post) VALUES(?,?,'owner',?,0)").bind(cid, me.id, now).run();
    return json({ channel: await chanView(await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first(), 'owner') });
  }
  if (p === 'channels/info' && !post) {
    const cid = Number(url.searchParams.get('id')); let a = await chanAccess(cid);
    if (!a && Number.isInteger(cid)) {                       // private channel: an invite code lets you look at the profile (so you can decide to join)
      const code = String(url.searchParams.get('code') || ''), c = code ? await db.prepare("SELECT * FROM channels WHERE id=? AND visibility='private'").bind(cid).first() : null;
      if (c && c.invite_code && safeEq(c.invite_code, code)) a = { c, role: null };
    }
    if (!a) return json({ error: 'Channel not found' }, 404);
    return json({ channel: await chanView(a.c, a.role) });
  }
  if (p === 'channels/update' && post) {
    const cid = Number(body.id), a = await chanAccess(cid);
    if (!a || !a.role) return json({ error: 'Channel not found' }, 404);
    if (a.role !== 'owner' && a.role !== 'admin') return json({ error: 'Only channel admins can edit the channel' }, 403);
    const c = a.c; let name = c.name, desc = c.description, avatar = c.avatar_key, vis = c.visibility, com = c.comments_on, code = c.invite_code;
    if (body.name !== undefined) { name = cleanName(body.name, 40); if (!name) return json({ error: 'Enter a channel name (max 40 characters)' }, 400); }
    if (body.description !== undefined) desc = cleanName(body.description, 300);
    if (body.comments_on !== undefined) com = body.comments_on ? 1 : 0;
    if (body.visibility !== undefined) { if (a.role !== 'owner') return json({ error: 'Only the owner can change visibility' }, 403); vis = body.visibility === 'private' ? 'private' : 'public'; }
    if (body.reset_invite) { if (a.role !== 'owner') return json({ error: 'Only the owner can reset the invite link' }, 403); code = rand(10); }
    if (body.avatar_key) { const cl = await claimMedia(body.avatar_key, 'image'); if (cl.err) return json({ error: cl.err }, 400); if (cl.msize > 250000) return json({ error: 'Channel picture is too large' }, 413); avatar = cl.key; }
    else if (body.remove_avatar) avatar = null;
    await db.prepare('UPDATE channels SET name=?,description=?,avatar_key=?,visibility=?,comments_on=?,invite_code=? WHERE id=?').bind(name, desc, avatar, vis, com, code, cid).run();
    if (c.avatar_key && c.avatar_key !== avatar) await dropAny(c.avatar_key);
    return json({ channel: await chanView(await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first(), a.role) });
  }
  if (p === 'channels/subscribe' && post) {
    const cid = Number(body.id), c = Number.isInteger(cid) ? await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first() : null;
    if (!c) return json({ error: 'Channel not found' }, 404);
    if (c.visibility === 'private' && !(await cRole(cid))) { const code = String(body.code || ''); if (!code || !c.invite_code || !safeEq(c.invite_code, code)) return json({ error: 'Channel not found' }, 404); }
    const last = (await db.prepare('SELECT MAX(id) m FROM channel_posts WHERE channel_id=?').bind(cid).first()).m || 0;
    await db.prepare("INSERT OR IGNORE INTO channel_members(channel_id,user_id,role,joined_at,last_seen_post) VALUES(?,?,'subscriber',?,?)").bind(cid, me.id, now, last).run();
    return json({ channel: await chanView(c, await cRole(cid)) });
  }
  if (p === 'channels/unsubscribe' && post) {
    const cid = Number(body.id), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role === 'owner') return json({ error: 'The owner cannot unsubscribe. Delete the channel instead.' }, 400);
    await db.prepare('DELETE FROM channel_members WHERE channel_id=? AND user_id=?').bind(cid, me.id).run();
    return json({ ok: true });
  }
  if (p === 'channels/subscribers' && !post) {
    const cid = Number(url.searchParams.get('id')), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role === 'subscriber') return json({ error: 'Only channel admins can see the subscriber list' }, 403);
    const { results } = await db.prepare("SELECT u.id,u.name,u.username,u.avatar_key,u.last_seen,cm.role,cm.joined_at FROM channel_members cm JOIN users u ON u.id=cm.user_id WHERE cm.channel_id=? ORDER BY CASE cm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, cm.joined_at LIMIT 500").bind(cid).all();
    return json({ subscribers: results.map(u => ({ ...publicUser(u, now), role: u.role })) });
  }
  if (p === 'channels/subscribers/remove' && post) {
    const cid = Number(body.id), uid = Number(body.user_id), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role === 'subscriber') return json({ error: 'Only channel admins can remove subscribers' }, 403);
    const t = await db.prepare('SELECT role FROM channel_members WHERE channel_id=? AND user_id=?').bind(cid, uid).first();
    if (!t || uid === me.id) return json({ error: 'Subscriber not found' }, 404);
    if (t.role === 'owner' || (t.role === 'admin' && role !== 'owner')) return json({ error: 'You cannot remove this person' }, 403);
    await db.prepare('DELETE FROM channel_members WHERE channel_id=? AND user_id=?').bind(cid, uid).run();
    return json({ ok: true });
  }
  if (p === 'channels/admins' && post) {
    const cid = Number(body.id), uid = Number(body.user_id), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role !== 'owner') return json({ error: 'Only the owner can add or remove admins' }, 403);
    if (body.role !== 'admin' && body.role !== 'subscriber') return json({ error: 'Invalid role' }, 400);
    const t = await db.prepare('SELECT role FROM channel_members WHERE channel_id=? AND user_id=?').bind(cid, uid).first();
    if (!t || uid === me.id || t.role === 'owner') return json({ error: 'Subscriber not found' }, 404);
    await db.prepare('UPDATE channel_members SET role=? WHERE channel_id=? AND user_id=?').bind(body.role, cid, uid).run();
    return json({ ok: true, role: body.role });
  }
  if (p === 'channels/delete' && post) {
    const cid = Number(body.id), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role !== 'owner') return json({ error: 'Only the owner can delete the channel' }, 403);
    await chanDrop(cid); return json({ ok: true });
  }
  if (p === 'channels/posts' && !post) {
    const cid = Number(url.searchParams.get('id')), a = await chanAccess(cid);
    if (!a) return json({ error: 'Channel not found' }, 404);
    const before = Number(url.searchParams.get('before')) || 0;
    const { results } = await db.prepare(`SELECT * FROM (SELECT p.*,u.name aname,(SELECT COUNT(*) FROM channel_comments cc WHERE cc.post_id=p.id AND cc.deleted_at IS NULL) ccount FROM channel_posts p LEFT JOIN users u ON u.id=p.author_id WHERE p.channel_id=?1 AND (?2=0 OR p.id<?2) ORDER BY p.id DESC LIMIT 50) ORDER BY id`).bind(cid, before).all();
    const ids = results.map(m => m.id), rx = new Map();
    if (ids.length) { const { results: rr } = await db.prepare(`SELECT post_id,emoji,user_id FROM channel_reactions WHERE post_id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all(); for (const r of rr) { const m = rx.get(r.post_id) || new Map(); const e = m.get(r.emoji) || { emoji: r.emoji, count: 0, mine: false }; e.count++; if (r.user_id === me.id) e.mine = true; m.set(r.emoji, e); rx.set(r.post_id, m); } }
    if (a.role && ids.length && !before) await db.prepare('UPDATE channel_members SET last_seen_post=MAX(last_seen_post,?3) WHERE channel_id=?1 AND user_id=?2').bind(cid, me.id, ids[ids.length - 1]).run();
    return json({ posts: results.map(m => postShape(m, rx.has(m.id) ? [...rx.get(m.id).values()] : [])), channel: await chanView(a.c, a.role), more: results.length === 50 });
  }
  if (p === 'channels/posts' && post) {
    const cid = Number(body.id), role = Number.isInteger(cid) ? await cRole(cid) : null;
    if (!role) return json({ error: 'Channel not found' }, 404);
    if (role === 'subscriber') return json({ error: 'Only channel admins can publish posts' }, 403);
    const text = String(body.body || '').trim(), type = ['text', 'image', 'video'].includes(body.type) ? body.type : 'text';
    if (text.length > 4000 || (type === 'text' && !text)) return json({ error: 'A post must be 1–4000 characters' }, 400);
    let key = null, mtype = null, msize = null, dur = null;
    if (type !== 'text') { const c = await claimMedia(body.media_key, type); if (c.err) return json({ error: c.err }, 400); key = c.key; mtype = c.mtype; msize = c.msize; dur = type === 'video' ? Math.min(3600, Math.max(0, Math.round(Number(body.duration) || 0))) : null; }
    const recent = await db.prepare('SELECT COUNT(*) n FROM channel_posts WHERE author_id=? AND created_at>?').bind(me.id, now - 10000).first();
    if (recent.n >= 10) return json({ error: 'You are posting too fast. Slow down.' }, 429);
    const r = await db.prepare('INSERT INTO channel_posts(channel_id,author_id,body,type,media_key,media_type,media_size,duration,created_at) VALUES(?,?,?,?,?,?,?,?,?)').bind(cid, me.id, text, type, key, mtype, msize, dur, now).run();
    await db.prepare('UPDATE channel_members SET last_seen_post=MAX(last_seen_post,?3) WHERE channel_id=?1 AND user_id=?2').bind(cid, me.id, r.meta.last_row_id).run();
    return json({ id: r.meta.last_row_id, created_at: now });
  }
  if (p === 'channels/posts/edit' && post) {
    const pid = Number(body.post_id), m = Number.isInteger(pid) ? await db.prepare('SELECT * FROM channel_posts WHERE id=? AND deleted_at IS NULL').bind(pid).first() : null;
    const role = m ? await cRole(m.channel_id) : null;
    if (!m || !role) return json({ error: 'Post not found' }, 404);
    if (m.author_id !== me.id || role === 'subscriber') return json({ error: 'You can only edit your own posts' }, 403);
    const text = String(body.body || '').trim();
    if (text.length > 4000 || (m.type === 'text' && !text)) return json({ error: 'A post must be 1–4000 characters' }, 400);
    await db.prepare('UPDATE channel_posts SET body=?,edited_at=? WHERE id=?').bind(text, now, pid).run();
    return json({ ok: true, edited_at: now });
  }
  if (p === 'channels/posts/delete' && post) {
    const pid = Number(body.post_id), m = Number.isInteger(pid) ? await db.prepare('SELECT * FROM channel_posts WHERE id=? AND deleted_at IS NULL').bind(pid).first() : null;
    const role = m ? await cRole(m.channel_id) : null;
    if (!m || !role) return json({ error: 'Post not found' }, 404);
    if (!((m.author_id === me.id && role !== 'subscriber') || role === 'owner')) return json({ error: 'You cannot delete this post' }, 403);
    await db.batch([db.prepare("UPDATE channel_posts SET deleted_at=?,body='',media_key=NULL WHERE id=?").bind(now, pid), db.prepare('DELETE FROM channel_reactions WHERE post_id=?').bind(pid), db.prepare('DELETE FROM channel_comments WHERE post_id=?').bind(pid)]);
    if (m.media_key) await dropAny(m.media_key);
    return json({ ok: true });
  }
  if (p === 'channels/react' && post) {
    const pid = Number(body.post_id), m = Number.isInteger(pid) ? await db.prepare('SELECT id,channel_id FROM channel_posts WHERE id=? AND deleted_at IS NULL').bind(pid).first() : null;
    if (!m || !(await cRole(m.channel_id))) return json({ error: 'Post not found' }, 404);
    const emoji = body.emoji;
    if (emoji === null || emoji === '') { await db.prepare('DELETE FROM channel_reactions WHERE post_id=? AND user_id=?').bind(pid, me.id).run(); return json({ ok: true, emoji: null }); }
    if (!EMOJIS.includes(emoji)) return json({ error: 'Reaction not allowed' }, 400);
    const cur = await db.prepare('SELECT emoji FROM channel_reactions WHERE post_id=? AND user_id=?').bind(pid, me.id).first();
    if (cur && cur.emoji === emoji) { await db.prepare('DELETE FROM channel_reactions WHERE post_id=? AND user_id=?').bind(pid, me.id).run(); return json({ ok: true, emoji: null }); }
    await db.prepare('INSERT INTO channel_reactions(post_id,user_id,emoji,created_at) VALUES(?1,?2,?3,?4) ON CONFLICT(post_id,user_id) DO UPDATE SET emoji=?3,created_at=?4').bind(pid, me.id, emoji, now).run();
    return json({ ok: true, emoji });
  }
  if (p === 'channels/comments' && !post) {
    const pid = Number(url.searchParams.get('post_id')), m = Number.isInteger(pid) ? await db.prepare('SELECT id,channel_id FROM channel_posts WHERE id=? AND deleted_at IS NULL').bind(pid).first() : null;
    const a = m ? await chanAccess(m.channel_id) : null;
    if (!a) return json({ error: 'Post not found' }, 404);
    const { results } = await db.prepare('SELECT cc.id,cc.user_id,cc.body,cc.created_at,u.name FROM channel_comments cc LEFT JOIN users u ON u.id=cc.user_id WHERE cc.post_id=? AND cc.deleted_at IS NULL ORDER BY cc.id LIMIT 200').bind(pid).all();
    return json({ comments: results.map(c => ({ id: c.id, user_id: c.user_id, name: c.name || 'Former member', body: c.body, created_at: c.created_at })), comments_on: !!a.c.comments_on });
  }
  if (p === 'channels/comments' && post) {
    const pid = Number(body.post_id), m = Number.isInteger(pid) ? await db.prepare('SELECT id,channel_id FROM channel_posts WHERE id=? AND deleted_at IS NULL').bind(pid).first() : null;
    const role = m ? await cRole(m.channel_id) : null;
    if (!m || !role) return json({ error: 'Post not found' }, 404);
    const c = await db.prepare('SELECT comments_on FROM channels WHERE id=?').bind(m.channel_id).first();
    if (!c.comments_on) return json({ error: 'Comments are turned off for this channel' }, 403);
    const text = String(body.body || '').trim();
    if (text.length < 1 || text.length > 500) return json({ error: 'A comment must be 1–500 characters' }, 400);
    const recent = await db.prepare('SELECT COUNT(*) n FROM channel_comments WHERE user_id=? AND created_at>?').bind(me.id, now - 10000).first();
    if (recent.n >= 8) return json({ error: 'You are commenting too fast. Slow down.' }, 429);
    const r = await db.prepare('INSERT INTO channel_comments(post_id,user_id,body,created_at) VALUES(?,?,?,?)').bind(pid, me.id, text, now).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }
  if (p === 'channels/comments/delete' && post) {
    const id = Number(body.id), c = Number.isInteger(id) ? await db.prepare('SELECT cc.id,cc.user_id,p.channel_id FROM channel_comments cc JOIN channel_posts p ON p.id=cc.post_id WHERE cc.id=? AND cc.deleted_at IS NULL').bind(id).first() : null;
    const role = c ? await cRole(c.channel_id) : null;
    if (!c || !role) return json({ error: 'Comment not found' }, 404);
    if (c.user_id !== me.id && role === 'subscriber') return json({ error: 'You cannot delete this comment' }, 403);
    await db.prepare('UPDATE channel_comments SET deleted_at=?,body=? WHERE id=?').bind(now, '', id).run();
    return json({ ok: true });
  }

  // =============== ACCOUNT MANAGEMENT ===============
  if (p === 'account' && !post) {
    const u = await db.prepare('SELECT id,name,username,email,phone,created_at FROM users WHERE id=?').bind(me.id).first();
    const pend = await db.prepare('SELECT new_email,expires_at FROM email_changes WHERE user_id=? AND expires_at>?').bind(me.id, now).first();
    const sc = await db.prepare('SELECT COUNT(*) n FROM sessions WHERE user_id=? AND MAX(last_used,created_at)>?').bind(me.id, now - SESSION_IDLE_MS).first();
    return json({ account: { name: u.name, username: u.username, phone: u.phone || null, sms: !!smsProvider(env), email: u.email || null, created_at: u.created_at || null, pending_email: pend ? pend.new_email : null, sessions: sc.n, email_service: !!(env.RESEND_API_KEY && env.MAIL_FROM) } });
  }
  if (p === 'account/username-check' && !post) {
    const u = String(url.searchParams.get('u') || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return json({ available: false, reason: 'Username: 3–20 letters, numbers or _' });
    if (RESERVED.has(u)) return json({ available: false, reason: 'This username is reserved' });
    const t = await db.prepare('SELECT id FROM users WHERE username=?').bind(u).first();
    if (t && t.id === me.id) return json({ available: false, reason: 'This is already your username' });
    return json({ available: !t, reason: t ? 'Username already taken' : '' });
  }
  if (p === 'account/username' && post) {
    const u = String(body.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return json({ error: 'Username: 3–20 letters, numbers or _' }, 400);
    if (RESERVED.has(u)) return json({ error: 'This username is reserved' }, 400);
    try { const r = await db.prepare('UPDATE users SET username=?1 WHERE id=?2 AND NOT EXISTS(SELECT 1 FROM users WHERE username=?1 AND id!=?2)').bind(u, me.id).run(); if (!r.meta.changes) { const same = await db.prepare('SELECT username FROM users WHERE id=?').bind(me.id).first(); return same && same.username === u ? json({ ok: true, username: u }) : json({ error: 'Username already taken' }, 409); } }
    catch (e) { if (/UNIQUE|constraint/i.test(String(e && e.message))) return json({ error: 'Username already taken' }, 409); throw e; }
    return json({ ok: true, username: u });
  }
  if (p === 'account/email/request' && post) {
    const email = String(body.email || '').trim().toLowerCase();
    if (!EMAIL.test(email) || email.length > 120) return json({ error: 'Enter a valid email address' }, 400);
    if (!(env.RESEND_API_KEY && env.MAIL_FROM)) return json({ error: 'Email verification is not set up on this server yet, so your email cannot be changed right now.', code: 'EMAIL_NOT_CONFIGURED' }, 503);
    const cur = await db.prepare('SELECT email FROM users WHERE id=?').bind(me.id).first();
    if (cur && cur.email === email) return json({ error: 'This is already your email' }, 400);
    const taken = await db.prepare('SELECT id FROM users WHERE email=? AND id!=?').bind(email, me.id).first();
    if (taken) return json({ error: 'This email is already used by another account' }, 409);
    const last = await db.prepare('SELECT created_at FROM email_changes WHERE user_id=?').bind(me.id).first();
    if (last && now - last.created_at < 60000) return json({ error: 'Please wait a minute before requesting another code' }, 429);
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0'), salt = rand(8);
    await db.prepare('INSERT INTO email_changes(user_id,new_email,code_hash,salt,attempts,expires_at,created_at) VALUES(?1,?2,?3,?4,0,?5,?6) ON CONFLICT(user_id) DO UPDATE SET new_email=?2,code_hash=?3,salt=?4,attempts=0,expires_at=?5,created_at=?6').bind(me.id, email, await sha(salt + code), salt, now + 900000, now).run();
    if (!(await sendMail(env, email, 'Your SUNLIGHT verification code', `Your SUNLIGHT code is ${code}. It expires in 15 minutes. If you did not ask to change your email, ignore this message.`))) {
      await db.prepare('DELETE FROM email_changes WHERE user_id=?').bind(me.id).run();
      return json({ error: 'The verification email could not be sent. Please try again later.', code: 'EMAIL_SEND_FAILED' }, 502);
    }
    return json({ ok: true, pending_email: email });
  }
  if (p === 'account/email/confirm' && post) {
    const code = String(body.code || '').trim();
    const c = await db.prepare('SELECT * FROM email_changes WHERE user_id=?').bind(me.id).first();
    if (!c || c.expires_at < now) return json({ error: 'No pending email change, or the code expired. Request a new code.' }, 400);
    if (c.attempts >= 5) { await db.prepare('DELETE FROM email_changes WHERE user_id=?').bind(me.id).run(); return json({ error: 'Too many wrong codes. Request a new code.' }, 429); }
    if (!/^\d{6}$/.test(code) || !safeEq(await sha(c.salt + code), c.code_hash)) { await db.prepare('UPDATE email_changes SET attempts=attempts+1 WHERE user_id=?').bind(me.id).run(); return json({ error: 'Wrong code' }, 400); }
    try { await db.prepare('UPDATE users SET email=? WHERE id=?').bind(c.new_email, me.id).run(); }
    catch (e) { if (/UNIQUE|constraint/i.test(String(e && e.message))) return json({ error: 'This email is already used by another account' }, 409); throw e; }
    await db.prepare('DELETE FROM email_changes WHERE user_id=?').bind(me.id).run();
    return json({ ok: true, email: c.new_email });
  }
  if (p === 'account/email/cancel' && post) { await db.prepare('DELETE FROM email_changes WHERE user_id=?').bind(me.id).run(); return json({ ok: true }); }
  // ---- link / change phone number (OTP to the NEW number) ----
  if (p === 'account/phone/request' && post) {
    const ph = phoneBody(body); if (ph.error) return json({ error: ph.error }, 400);
    const cur = await db.prepare('SELECT phone FROM users WHERE id=?').bind(me.id).first();
    if (cur && cur.phone === ph.e164) return json({ error: 'This is already your number' }, 400);
    const taken = await db.prepare('SELECT id FROM users WHERE phone=? AND id!=?').bind(ph.e164, me.id).first();
    if (taken) return json({ error: 'This number is already registered to another account' }, 409);
    return otpIssue(env, req, now, ph.e164, 'link', me.id);
  }
  if (p === 'account/phone/verify' && post) {
    const ph = phoneBody(body); if (ph.error) return json({ error: ph.error }, 400);
    const cur = await db.prepare('SELECT phone FROM users WHERE id=?').bind(me.id).first();
    const c = await otpCheck(env, req, now, ph.e164, 'link', me.id, body.code); if (c.res) return c.res;
    try { await db.prepare('UPDATE users SET phone=?,phone_verified_at=? WHERE id=?').bind(ph.e164, now, me.id).run(); }
    catch (e) { if (/UNIQUE|constraint/i.test(String(e && e.message))) return json({ error: 'This number is already registered to another account' }, 409); throw e; }
    if (cur && cur.phone) await db.prepare('DELETE FROM sessions WHERE user_id=? AND token!=?').bind(me.id, tok).run();   // a changed number signs other devices out
    return json({ ok: true, phone: ph.e164 });
  }
  if (p === 'account/delete/request' && post) {
    const u = await db.prepare('SELECT phone FROM users WHERE id=?').bind(me.id).first();
    if (!u || !u.phone) return json({ error: 'Link your phone number first' }, 400);
    return otpIssue(env, req, now, u.phone, 'delete', me.id);
  }
  if (p === 'account/logout-others' && post) {
    await db.prepare('DELETE FROM sessions WHERE user_id=? AND token!=?').bind(me.id, tok).run();
    return json({ ok: true });
  }
  if (p === 'account/delete' && post) {
    if (String(body.confirm || '') !== 'DELETE') return json({ error: 'Type DELETE to confirm' }, 400);
    const du = await db.prepare('SELECT phone,pass_hash,salt FROM users WHERE id=?').bind(me.id).first();
    if (du && du.phone) { const c = await otpCheck(env, req, now, du.phone, 'delete', me.id, body.code); if (c.res) return c.res; }
    else if (!(du && du.pass_hash && safeEq(await hashPw(String(body.password || ''), du.salt), du.pass_hash))) return json({ error: 'Link your phone number to delete your account, or enter your old password' }, 403);
    const id = me.id;
    const { results: keys } = await db.prepare('SELECT key FROM media WHERE owner_id=?').bind(id).all();
    for (const k of keys) await dropAny(k.key);
    { const { results: gs } = await db.prepare('SELECT group_id FROM group_members WHERE user_id=?').bind(id).all(); for (const g of gs) await groupLeave(g.group_id, id); }
    { const { results: cs } = await db.prepare('SELECT id FROM channels WHERE owner_id=?').bind(id).all(); for (const c of cs) await chanDrop(c.id); }
    await db.batch(['DELETE FROM channel_members WHERE user_id=?1', 'DELETE FROM channel_reactions WHERE user_id=?1', 'DELETE FROM channel_comments WHERE user_id=?1', "UPDATE channel_posts SET deleted_at=CAST(strftime('%s','now') AS INTEGER)*1000, body='', media_key=NULL WHERE author_id=?1 AND deleted_at IS NULL"].map(q => db.prepare(q).bind(id)));
    await db.batch([
      'DELETE FROM call_signals WHERE to_user=?1 OR call_id IN (SELECT id FROM calls WHERE caller_id=?1 OR callee_id=?1)', 'DELETE FROM calls WHERE caller_id=?1 OR callee_id=?1',
      'DELETE FROM status_likes WHERE user_id=?1 OR status_id IN (SELECT id FROM statuses WHERE user_id=?1)', 'DELETE FROM status_views WHERE viewer_id=?1 OR status_id IN (SELECT id FROM statuses WHERE user_id=?1)',
      'DELETE FROM notifications WHERE user_id=?1 OR actor_id=?1', 'DELETE FROM statuses WHERE user_id=?1',
      'DELETE FROM messages WHERE sender_id=?1 OR receiver_id=?1', 'DELETE FROM contacts WHERE owner_id=?1 OR contact_id=?1', 'DELETE FROM blocks WHERE blocker_id=?1 OR blocked_id=?1',
      'DELETE FROM chat_prefs WHERE user_id=?1 OR peer_id=?1', 'DELETE FROM user_prefs WHERE user_id=?1', 'DELETE FROM email_changes WHERE user_id=?1', 'DELETE FROM otp_requests WHERE user_id=?1', 'DELETE FROM sessions WHERE user_id=?1', 'DELETE FROM users WHERE id=?1'
    ].map(q => db.prepare(q).bind(id)));
    return json({ ok: true });
  }

  // =============== NOTIFICATION PREFERENCES ===============
  if (p === 'settings/notifications' && !post) {
    const r = await db.prepare('SELECT notif FROM user_prefs WHERE user_id=?').bind(me.id).first();
    return json({ prefs: cleanPrefs(r && r.notif), tones: TONES });
  }
  if (p === 'settings/notifications' && post) {
    const r = await db.prepare('SELECT notif FROM user_prefs WHERE user_id=?').bind(me.id).first();
    const next = cleanPrefs({ ...cleanPrefs(r && r.notif), ...(body.prefs && typeof body.prefs === 'object' ? body.prefs : {}) });
    await db.prepare('INSERT INTO user_prefs(user_id,notif,updated_at) VALUES(?1,?2,?3) ON CONFLICT(user_id) DO UPDATE SET notif=?2,updated_at=?3').bind(me.id, JSON.stringify(next), now).run();
    return json({ prefs: next });
  }
  if (p === 'settings/notifications/reset' && post) {
    await db.prepare('DELETE FROM user_prefs WHERE user_id=?').bind(me.id).run();
    return json({ prefs: { ...NOTIF_DEFAULTS } });
  }

  // =============== HELP: SUPPORT REQUESTS ===============
  if (p === 'support' && post) {
    const subject = String(body.subject || '').trim(), message = String(body.message || '').trim();
    if (subject.length < 3 || subject.length > 100) return json({ error: 'Subject must be 3–100 characters' }, 400);
    if (message.length < 10 || message.length > 2000) return json({ error: 'Describe the problem in 10–2000 characters' }, 400);
    const recent = await db.prepare('SELECT COUNT(*) n FROM support_requests WHERE user_id=? AND created_at>?').bind(me.id, now - 3600000).first();
    if (recent.n >= 5) return json({ error: 'You have sent several requests already. Please wait a while.' }, 429);
    const r = await db.prepare('INSERT INTO support_requests(user_id,subject,message,status,created_at) VALUES(?,?,?,?,?)').bind(me.id, subject, message, 'open', now).run();
    return json({ ok: true, request: { id: r.meta.last_row_id, subject, status: 'open', created_at: now } });
  }
  if (p === 'support' && !post) {
    const { results } = await db.prepare('SELECT id,subject,message,status,created_at FROM support_requests WHERE user_id=? ORDER BY id DESC LIMIT 20').bind(me.id).all();
    return json({ requests: results });
  }

  if (p === 'chats') {
    await db.prepare('UPDATE messages SET delivered_at=? WHERE receiver_id=? AND delivered_at IS NULL').bind(now, me.id).run();
    const { results } = await db.prepare(`
      SELECT u.id,u.name,u.avatar_key,u.last_seen,m.body last_body,m.type last_type,m.created_at last_at,m.sender_id last_sender,m.read_at last_read,m.delivered_at last_delivered,
        m.deleted_at last_deleted,m.id last_id,m.status_id last_status,
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
      db.prepare(`DELETE FROM media_chunks WHERE key IN (SELECT key FROM media WHERE owner_id=? AND created_at<? AND key NOT IN ${REFS})`).bind(me.id, old),
      db.prepare(`DELETE FROM media WHERE owner_id=? AND created_at<? AND key NOT IN ${REFS}`).bind(me.id, old)
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
    const stale = (await db.prepare(`SELECT key FROM media WHERE owner_id=? AND created_at<? AND type LIKE 'video/%' AND key NOT IN ${REFS} LIMIT 10`).bind(me.id, old).all()).results;
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
      await db.prepare('SELECT 1 ok FROM group_messages gm JOIN group_members m ON m.group_id=gm.group_id WHERE gm.media_key=? AND gm.deleted_at IS NULL AND m.user_id=?').bind(key, me.id).first() ||   // group media: members only
      await db.prepare('SELECT 1 ok FROM groups g JOIN group_members m ON m.group_id=g.id WHERE g.avatar_key=? AND m.user_id=?').bind(key, me.id).first() ||
      await db.prepare("SELECT 1 ok FROM channel_posts p JOIN channels c ON c.id=p.channel_id WHERE p.media_key=? AND p.deleted_at IS NULL AND (c.visibility='public' OR EXISTS(SELECT 1 FROM channel_members m WHERE m.channel_id=c.id AND m.user_id=?))").bind(key, me.id).first() ||   // public channels are readable by anyone signed in; private ones by members only
      await db.prepare("SELECT 1 ok FROM channels c WHERE c.avatar_key=? AND (c.visibility='public' OR EXISTS(SELECT 1 FROM channel_members m WHERE m.channel_id=c.id AND m.user_id=?))").bind(key, me.id).first() ||
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
