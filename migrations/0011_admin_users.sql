-- Admin Users Management: lets an administrator suspend / reactivate an account. Non-destructive: one nullable column.
-- (The Worker also adds this column automatically; run this only if you manage migrations by hand and the column does not exist yet.)
ALTER TABLE users ADD COLUMN suspended_at INTEGER;
