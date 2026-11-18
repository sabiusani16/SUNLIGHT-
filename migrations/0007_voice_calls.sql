-- voice calls (0007)
CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'ringing', created_at INTEGER NOT NULL, ringing_at INTEGER, answered_at INTEGER, ended_at INTEGER, end_reason TEXT, duration INTEGER NOT NULL DEFAULT 0, caller_beat INTEGER NOT NULL DEFAULT 0, callee_beat INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id, id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id, id);
CREATE TABLE IF NOT EXISTS call_signals (id INTEGER PRIMARY KEY AUTOINCREMENT, call_id INTEGER NOT NULL, to_user INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_signals_to ON call_signals(to_user, call_id, id);
