-- Settings: notification preferences, email-change verification, support requests, per-chat call-history clear time.
-- Non-destructive (CREATE IF NOT EXISTS). The Worker also creates these automatically on first request.
CREATE TABLE IF NOT EXISTS user_prefs (user_id INTEGER PRIMARY KEY, notif TEXT, updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS email_changes (user_id INTEGER PRIMARY KEY, new_email TEXT NOT NULL, code_hash TEXT NOT NULL, salt TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS support_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_support_user ON support_requests(user_id, id);
CREATE INDEX IF NOT EXISTS idx_calls_pair ON calls(caller_id, callee_id);
-- chat_prefs.cleared_at is added by the Worker (ALTER TABLE chat_prefs ADD COLUMN cleared_at INTEGER NOT NULL DEFAULT 0).
