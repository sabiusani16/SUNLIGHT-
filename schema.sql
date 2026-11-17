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
