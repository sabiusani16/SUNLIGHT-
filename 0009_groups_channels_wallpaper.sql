-- Groups, Channels (non-destructive; the Worker also creates these automatically).
-- Wallpapers need no new tables: they live in chat_prefs.theme (JSON) and reuse the media tables.
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
