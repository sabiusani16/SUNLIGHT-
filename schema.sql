-- FRESH database only. For an EXISTING database run the files in migrations/ instead (they add new columns without touching your data).
-- SUNLIGHT schema (the Worker also applies this automatically on first request)
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  avatar_key TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  type TEXT NOT NULL DEFAULT 'text',
  media_key TEXT,
  media_type TEXT,
  media_size INTEGER,
  duration INTEGER,
  reply_to INTEGER,
  delivered_at INTEGER,
  deleted_at INTEGER,
  status_id INTEGER,
  status_snap TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id, receiver_id, id);
CREATE INDEX IF NOT EXISTS idx_msg_recv ON messages(receiver_id, read_at);

-- Contacts: each row = "owner_id saved contact_id in their contact list"
CREATE TABLE IF NOT EXISTS contacts (
  owner_id INTEGER NOT NULL,
  contact_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, contact_id)   -- prevents duplicate contacts
);
CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id);
CREATE INDEX IF NOT EXISTS idx_msg_media ON messages(media_key);
CREATE INDEX IF NOT EXISTS idx_msg_deliv ON messages(receiver_id, delivered_at);

-- Photos and voice notes live in D1 (no R2 / no card needed). Files are split into small chunks.
CREATE TABLE IF NOT EXISTS media (
  key TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS media_chunks (
  key TEXT NOT NULL,
  idx INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY (key, idx)
);
CREATE TABLE IF NOT EXISTS statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, body TEXT, caption TEXT, bg INTEGER, media_key TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_status_user ON statuses(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_status_media ON statuses(media_key);
CREATE TABLE IF NOT EXISTS status_views (status_id INTEGER NOT NULL, viewer_id INTEGER NOT NULL, viewed_at INTEGER NOT NULL, PRIMARY KEY (status_id, viewer_id));
CREATE TABLE IF NOT EXISTS chat_prefs (user_id INTEGER NOT NULL, peer_id INTEGER NOT NULL, theme TEXT, cleared_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, peer_id));
CREATE TABLE IF NOT EXISTS blocks (blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (blocker_id, blocked_id));
CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);
CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, reported_id INTEGER NOT NULL, message_id INTEGER, message_text TEXT, reason TEXT NOT NULL, details TEXT, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_reports_reported ON reports(reported_id, created_at);
CREATE TABLE IF NOT EXISTS status_likes (status_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (status_id, user_id));
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, actor_id INTEGER NOT NULL, status_id INTEGER, created_at INTEGER NOT NULL, read_at INTEGER, UNIQUE (user_id, type, actor_id, status_id));
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, id);

-- voice calls (0007)
CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'ringing', created_at INTEGER NOT NULL, ringing_at INTEGER, answered_at INTEGER, ended_at INTEGER, end_reason TEXT, duration INTEGER NOT NULL DEFAULT 0, caller_beat INTEGER NOT NULL DEFAULT 0, callee_beat INTEGER NOT NULL DEFAULT 0, video INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id, id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id, id);
CREATE TABLE IF NOT EXISTS call_signals (id INTEGER PRIMARY KEY AUTOINCREMENT, call_id INTEGER NOT NULL, to_user INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_signals_to ON call_signals(to_user, call_id, id);
CREATE TABLE IF NOT EXISTS user_prefs (user_id INTEGER PRIMARY KEY, notif TEXT, updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS email_changes (user_id INTEGER PRIMARY KEY, new_email TEXT NOT NULL, code_hash TEXT NOT NULL, salt TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS support_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL);

-- groups & channels
CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', avatar_key TEXT, created_by INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL, added_by INTEGER, PRIMARY KEY (group_id, user_id));
CREATE INDEX IF NOT EXISTS idx_gm_user ON group_members(user_id);
CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, body TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT 'text', media_key TEXT, media_type TEXT, media_size INTEGER, duration INTEGER, reply_to INTEGER, created_at INTEGER NOT NULL, deleted_at INTEGER);
CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id, id);
CREATE TABLE IF NOT EXISTS group_reactions (message_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (message_id, user_id));
CREATE TABLE IF NOT EXISTS group_reads (group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, last_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (group_id, user_id));
CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', avatar_key TEXT, owner_id INTEGER NOT NULL, visibility TEXT NOT NULL DEFAULT 'public', comments_on INTEGER NOT NULL DEFAULT 1, invite_code TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS channel_members (channel_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'subscriber', joined_at INTEGER NOT NULL, last_seen_post INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, user_id));
CREATE INDEX IF NOT EXISTS idx_cm_user ON channel_members(user_id);
CREATE TABLE IF NOT EXISTS channel_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id INTEGER NOT NULL, author_id INTEGER NOT NULL, body TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT 'text', media_key TEXT, media_type TEXT, media_size INTEGER, duration INTEGER, created_at INTEGER NOT NULL, edited_at INTEGER, deleted_at INTEGER);
CREATE INDEX IF NOT EXISTS idx_cp_channel ON channel_posts(channel_id, id);
CREATE TABLE IF NOT EXISTS channel_reactions (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (post_id, user_id));
CREATE TABLE IF NOT EXISTS channel_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, deleted_at INTEGER);
CREATE INDEX IF NOT EXISTS idx_cc_post ON channel_comments(post_id, id);
