-- Phone + SMS OTP authentication. Non-destructive: only adds columns/tables/indexes. No user, message or session data is touched.
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN phone_verified_at INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL;
ALTER TABLE sessions ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN ua TEXT;
CREATE TABLE IF NOT EXISTS otp_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, purpose TEXT NOT NULL, user_id INTEGER, code_hash TEXT NOT NULL, salt TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, consumed_at INTEGER, ip_hash TEXT);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_requests(phone, created_at);
CREATE INDEX IF NOT EXISTS idx_otp_ip ON otp_requests(ip_hash, created_at);
CREATE TABLE IF NOT EXISTS signup_tickets (hash TEXT PRIMARY KEY, phone TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_fails (k TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_auth_fails ON auth_fails(k, at);
