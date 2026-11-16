-- Run ONCE on an existing database (the Worker also adds this column automatically if you skip it).
ALTER TABLE users ADD COLUMN avatar_key TEXT;
