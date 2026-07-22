"""
Phase 2 Link Probe: secure_doc.db
Initializes the application database schema and verifies connectivity.
Tables: users, honeysets, real_index
Tables: users, honeysets, real_index, real_vault_sessions
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'secure_doc.db')

SCHEMA = """
-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    created_at   TEXT NOT NULL,
    is_locked    INTEGER NOT NULL DEFAULT 0,
    vault_path   TEXT NOT NULL
);

-- Honeysets table: stores all 20 hashes per user (opaque — no is_real flag here)
CREATE TABLE IF NOT EXISTS honeysets (
    set_id       TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(user_id),
    hash_index   INTEGER NOT NULL,   -- position 0–19 in the shuffled set
    pw_hash      TEXT NOT NULL       -- PBKDF2-HMAC-SHA256 derived hash
);

-- Hardened real_index table: isolated record of which index is the real password
-- Kept in a separate table to enforce logical separation from honeysets
CREATE TABLE IF NOT EXISTS real_index (
    user_id      TEXT PRIMARY KEY REFERENCES users(user_id),
    real_idx     INTEGER NOT NULL    -- the shuffled position of the real password
);

-- Server-side real vault sessions: stores the derived key behind an opaque token
CREATE TABLE IF NOT EXISTS real_vault_sessions (
    session_token TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    vault_key     BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_real_vault_sessions_user_id
    ON real_vault_sessions(user_id);
"""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA)
    conn.commit()

    # Verify all three tables exist
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    return tables

if __name__ == '__main__':
    tables = init_db()
    print(f"[DB PROBE] secure_doc.db initialised at: {os.path.abspath(DB_PATH)}")
    print(f"[DB PROBE] Tables confirmed: {tables}")
    # Verify write access with a test transaction then rollback
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("BEGIN;")
        conn.execute("INSERT INTO users VALUES ('test-uuid','__probe__','2024-01-01',0,'vault/real/__probe__/');")
        conn.execute("ROLLBACK;")
        print("[DB PROBE] Write/rollback test: PASS")
    except Exception as e:
        print(f"[DB PROBE] Write test FAILED: {e}")
    finally:
        conn.close()
