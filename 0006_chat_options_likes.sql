-- Chat options (theme / clear chat / block / report) and status likes + notifications.
-- Only NEW tables are created: nothing existing is altered or deleted.
-- (The Worker also creates these automatically; running this by hand is optional.)
CREATE TABLE IF NOT EXISTS chat_prefs (user_id INTEGER NOT NULL, peer_id INTEGER NOT NULL, theme TEXT, cleared_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, peer_id));
CREATE TABLE IF NOT EXISTS blocks (blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (blocker_id, blocked_id));
CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);
CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, reported_id INTEGER NOT NULL, message_id INTEGER, message_text TEXT, reason TEXT NOT NULL, details TEXT, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_reports_reported ON reports(reported_id, created_at);
CREATE TABLE IF NOT EXISTS status_likes (status_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (status_id, user_id));
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, actor_id INTEGER NOT NULL, status_id INTEGER, created_at INTEGER NOT NULL, read_at INTEGER, UNIQUE (user_id, type, actor_id, status_id));
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, id);
