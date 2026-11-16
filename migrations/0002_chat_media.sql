-- Run ONCE on an existing database (the Worker also adds these columns automatically if you skip this).
-- Chat features: message types (text / image / voice), media, replies, delivery + deletion
ALTER TABLE messages ADD COLUMN type TEXT NOT NULL DEFAULT 'text';
ALTER TABLE messages ADD COLUMN media_key TEXT;
ALTER TABLE messages ADD COLUMN media_type TEXT;
ALTER TABLE messages ADD COLUMN media_size INTEGER;
ALTER TABLE messages ADD COLUMN duration INTEGER;
ALTER TABLE messages ADD COLUMN reply_to INTEGER;
ALTER TABLE messages ADD COLUMN delivered_at INTEGER;
ALTER TABLE messages ADD COLUMN deleted_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_msg_media ON messages(media_key);
CREATE INDEX IF NOT EXISTS idx_msg_deliv ON messages(receiver_id, delivered_at);
