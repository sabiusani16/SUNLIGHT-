-- Reports management + support conversations (non-destructive; the app also applies these automatically on first request)
ALTER TABLE reports ADD COLUMN evidence_key TEXT;
ALTER TABLE reports ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reports ADD COLUMN reviewed_by INTEGER;
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, id);
CREATE TABLE IF NOT EXISTS report_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, admin_id INTEGER NOT NULL, note TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_report_notes ON report_notes(report_id, id);
ALTER TABLE support_requests ADD COLUMN category TEXT NOT NULL DEFAULT 'contact';
ALTER TABLE support_requests ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE support_requests ADD COLUMN user_unread INTEGER NOT NULL DEFAULT 0;
ALTER TABLE support_requests ADD COLUMN admin_unread INTEGER NOT NULL DEFAULT 1;
ALTER TABLE support_requests ADD COLUMN media_key TEXT;
CREATE INDEX IF NOT EXISTS idx_support_status ON support_requests(status, updated_at);
CREATE TABLE IF NOT EXISTS support_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER NOT NULL, sender TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', media_key TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_support_msg ON support_messages(request_id, id);
