-- Admin Users Management: lets an administrator suspend / reactivate an account. Non-destructive: one nullable column.
-- (The Worker also adds this column automatically; run this only if you manage migrations by hand and the column does not exist yet.)
ALTER TABLE users ADD COLUMN suspended_at INTEGER;
-- Admin audit log (who reset / edited / suspended whom; never passwords or message text)
CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, target_id INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_admin_log_target ON admin_log(target_id, id);
