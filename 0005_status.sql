-- Status (24h) – safe to run more than once; the Worker also creates these automatically.
CREATE TABLE IF NOT EXISTS statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, body TEXT, caption TEXT, bg INTEGER, media_key TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_status_user ON statuses(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_status_media ON statuses(media_key);
CREATE TABLE IF NOT EXISTS status_views (status_id INTEGER NOT NULL, viewer_id INTEGER NOT NULL, viewed_at INTEGER NOT NULL, PRIMARY KEY (status_id, viewer_id));
