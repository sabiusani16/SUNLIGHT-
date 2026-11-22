-- Typing / recording indicator. Non-destructive: one new small table.
CREATE TABLE IF NOT EXISTS chat_activity (user_id INTEGER NOT NULL, peer_id INTEGER NOT NULL, state TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (user_id, peer_id));
