"""
account_lock.py — Real-Account Brute-Force Lockout
==================================================
Secure-Doc · A.N.T. Architecture

Locks a REAL account after MAX_FAILED consecutive failed logins, for
LOCK_MINUTES. State is persisted in the shared backend (SQLite locally, or
Supabase Postgres when configured), so it survives a cookie clear or a server
restart — unlike the in-session `session_attempts` counter, which only drives
the honey escalation logic (Rule 4.2) and is trivially reset by dropping cookies.

HONEYPOT EXEMPTION (Rule 1 — Honey Mode Silence):
  This module is NEVER told about HONEY logins. app.py calls record_failure()
  only on a FAILED outcome and reset() only on a genuine REAL login. A HONEY
  outcome (an intruder who matched a honeyword) touches neither, so the
  honeypot stays open no matter how many times the decoy password is used —
  the intruder is kept engaged instead of being locked out.

Counting is keyed on the *typed username* (existing or not) so the lock behaves
identically for real and unknown usernames — no username-enumeration signal.
"""

from datetime import datetime, timezone, timedelta

import db_backend
from db_backend import PH

# ── Policy ──────────────────────────────────────────────────────────────────
MAX_FAILED   = 5    # failed attempts allowed before the account is locked
LOCK_MINUTES = 15   # how long the lock lasts once triggered

_table_ready = False


def _ensure_table() -> None:
    """Creates the login_attempts table on first use (safe to call repeatedly)."""
    global _table_ready
    if _table_ready:
        return
    conn = db_backend.connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                username     TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_failure TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    _table_ready = True


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _effective_count(failed_count, locked_until_raw, now: datetime) -> int:
    """
    The count that still applies right now. A lock that has already expired
    resets the tally to zero so the next failure starts a fresh window.
    """
    count = failed_count or 0
    locked_until = _parse(locked_until_raw)
    if locked_until is not None and locked_until <= now:
        return 0
    return count


def lock_status(username: str) -> tuple[bool, int]:
    """
    Returns (is_locked, seconds_remaining) for a username, without mutating state.
    seconds_remaining is 0 when not locked.
    """
    _ensure_table()
    conn = db_backend.connect()
    try:
        row = conn.execute(
            f"SELECT locked_until FROM login_attempts WHERE username={PH}",
            (username,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return False, 0
    locked_until = _parse(row[0])
    if locked_until is None:
        return False, 0
    remaining = (locked_until - _now()).total_seconds()
    return (True, int(remaining)) if remaining > 0 else (False, 0)


def record_failure(username: str) -> tuple[bool, int]:
    """
    Registers one failed login for `username`. When the running count reaches
    MAX_FAILED the account is locked for LOCK_MINUTES.

    Returns (is_locked, seconds_remaining) reflecting the state AFTER this
    failure — so the caller can show the lock message on the very attempt that
    trips the threshold.
    """
    _ensure_table()
    now = _now()
    conn = db_backend.connect()
    try:
        row = conn.execute(
            f"SELECT failed_count, locked_until FROM login_attempts WHERE username={PH}",
            (username,)
        ).fetchone()

        prior = _effective_count(row[0] if row else 0,
                                 row[1] if row else None, now)
        new_count    = prior + 1
        locked_until = None
        if new_count >= MAX_FAILED:
            locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()

        if row:
            conn.execute(
                f"UPDATE login_attempts SET failed_count={PH}, locked_until={PH}, "
                f"last_failure={PH} WHERE username={PH}",
                (new_count, locked_until, now.isoformat(), username)
            )
        else:
            conn.execute(
                f"INSERT INTO login_attempts (username, failed_count, locked_until, "
                f"last_failure) VALUES ({PH},{PH},{PH},{PH})",
                (username, new_count, locked_until, now.isoformat())
            )
        conn.commit()
    finally:
        conn.close()

    if locked_until:
        return True, LOCK_MINUTES * 60
    return False, 0


def reset(username: str) -> None:
    """Clears all failure/lock state for a username — called on a genuine REAL login."""
    _ensure_table()
    conn = db_backend.connect()
    try:
        conn.execute(f"DELETE FROM login_attempts WHERE username={PH}", (username,))
        conn.commit()
    finally:
        conn.close()


def attempts_remaining(username: str) -> int:
    """Failed attempts left before the account locks (for a friendly warning)."""
    _ensure_table()
    conn = db_backend.connect()
    try:
        row = conn.execute(
            f"SELECT failed_count, locked_until FROM login_attempts WHERE username={PH}",
            (username,)
        ).fetchone()
    finally:
        conn.close()
    prior = _effective_count(row[0] if row else 0,
                             row[1] if row else None, _now())
    return max(0, MAX_FAILED - prior)
