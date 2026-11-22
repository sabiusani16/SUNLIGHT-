-- Safe to run any time (IF NOT EXISTS). The Worker also creates these tables automatically.
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
