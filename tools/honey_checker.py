"""
honey_checker.py — Layer 2: Chaffing-and-Winnowing Login Arbiter
=================================================================
Secure-Doc · Phase 3 · A.N.T. Architecture

Implements the full Juels & Rivest Chaffing-and-Winnowing model:

  REGISTRATION  →  generate_honeyset(username, real_password)
                   Produces n=20 PBKDF2 hashes (1 real + 19 decoys),
                   stores them in secure_doc.db, creates vault salts.

  LOGIN         →  check_login(username, password_attempt, session)
                   Returns a LoginResult named tuple:
                     .outcome  : 'REAL' | 'HONEY' | 'FAILED'
                     .user_id  : str | None
                     .honey_index : int | None  (matched position, HONEY only)

Rule 4.2 (Escalation):
  The Flask session object carries 'session_attempts' (int).
  This module increments it on FAILED, reads it on HONEY to determine
  alert_level. It never persists session_attempts to the DB.

Behavioral Invariants:
  - Timing: all 20 hashes are always checked — no early exit on first match.
    This prevents timing side-channels that could reveal set density.
  - HONEY path: caller (app.py) is responsible for issuing the decoy session
    and calling audit_logger.log_honey_event(). This module only returns the result.
"""

import hashlib
import os
import secrets
import uuid
from collections import namedtuple
from typing import Optional

import db_backend
from db_backend import PH

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
# Kept for reference; the active connection is chosen by db_backend
# (SQLite locally, or Supabase Postgres when SUPABASE_DB_URL is set).
DB_PATH   = db_backend.SQLITE_PATH

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HONEY_N           = 20           # total set size
PBKDF2_ITERATIONS = 200_000
PBKDF2_DKLEN      = 32

# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------
LoginResult = namedtuple('LoginResult', ['outcome', 'user_id', 'honey_index'])


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------
def _derive_hash(password: str, salt: bytes) -> str:
    """Returns hex-encoded PBKDF2-HMAC-SHA256 digest."""
    raw = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_DKLEN
    )
    return raw.hex()


# ---------------------------------------------------------------------------
# Decoy password generator
# ---------------------------------------------------------------------------
_BASES   = [
    "summer", "winter", "dragon", "shadow", "falcon", "thunder", "silver",
    "matrix", "cobra", "phantom", "ranger", "rocket", "falcon", "echo",
    "titan", "viper", "blaze", "storm", "nova", "cipher", "zenith"
]
_LEET    = str.maketrans('aeiost', '4310$7')
_SYMBOLS = ['!', '@', '#', '$', '&']

def _generate_decoy_passwords(n: int = 19) -> list[str]:
    """
    Produces n plausible-looking decoy passwords via character mutation.
    Method: Chaffing-and-Winnowing — chaff passwords are computationally
    indistinguishable from the real password at the hash level.
    """
    rng   = secrets.SystemRandom()
    decoys: list[str] = []
    while len(decoys) < n:
        base   = rng.choice(_BASES)
        suffix = str(rng.randint(10, 9999))
        symbol = rng.choice(_SYMBOLS) if rng.random() > 0.4 else ''
        leet   = base.translate(_LEET) if rng.random() > 0.5 else base
        candidate = f"{leet}{suffix}{symbol}"
        if candidate not in decoys:
            decoys.append(candidate)
    return decoys


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
def register_user(username: str, real_password: str) -> dict:
    """
    Registers a new user with a full n=20 Chaffing-and-Winnowing honeyset.

    Steps:
      1. Generate per-user honeyset salt (stored in users table).
      2. Generate per-user vault salt (used by crypto_engine for AES/XOR keys).
      3. Derive PBKDF2 hash of real_password.
      4. Generate 19 decoy passwords and derive their hashes.
      5. Shuffle all 20 hashes; record real_index in hardened table.
      6. Write to secure_doc.db inside a single transaction.

    Returns dict with user_id, vault_path, honeyset_salt (hex), vault_salt (hex).
    Raises ValueError if username already exists.
    """
    conn = db_backend.connect()

    # Guard: unique username
    row = conn.execute(f"SELECT 1 FROM users WHERE username={PH}", (username,)).fetchone()
    if row:
        conn.close()
        raise ValueError(f"Username '{username}' is already registered.")

    # Salts
    user_id       = str(uuid.uuid4())
    honeyset_salt = os.urandom(32)
    vault_salt    = os.urandom(32)
    vault_path    = f"vault/real/{user_id}/"

    # Build honeyset
    real_hash    = _derive_hash(real_password, honeyset_salt)
    decoy_pwds   = _generate_decoy_passwords(HONEY_N - 1)
    decoy_hashes = [_derive_hash(d, honeyset_salt) for d in decoy_pwds]

    full_set = [real_hash] + decoy_hashes          # real at index 0 before shuffle
    indices  = list(range(HONEY_N))
    rng      = secrets.SystemRandom()
    rng.shuffle(indices)                            # cryptographically random shuffle
    shuffled = [full_set[i] for i in indices]
    real_shuffled_idx = indices.index(0)            # where did real_hash land?

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    try:
        conn.execute(
            f"INSERT INTO users VALUES ({','.join([PH]*7)})",
            (user_id, username, now, 0, vault_path,
             honeyset_salt.hex(), vault_salt.hex())
        )
        for pos, pw_hash in enumerate(shuffled):
            set_id = str(uuid.uuid4())
            conn.execute(
                f"INSERT INTO honeysets VALUES ({','.join([PH]*4)})",
                (set_id, user_id, pos, pw_hash)
            )
        conn.execute(
            f"INSERT INTO real_index VALUES ({PH},{PH})",
            (user_id, real_shuffled_idx)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise ValueError(f"DB integrity error during registration: {e}")

    conn.close()

    # Create vault directories
    os.makedirs(os.path.join(_BASE_DIR, vault_path), exist_ok=True)
    os.makedirs(os.path.join(_BASE_DIR, f"vault/decoy/{user_id}/"), exist_ok=True)

    return {
        "user_id":        user_id,
        "vault_path":     vault_path,
        "honeyset_salt":  honeyset_salt.hex(),
        "vault_salt":     vault_salt.hex(),
    }


# ---------------------------------------------------------------------------
# Login arbiter
# ---------------------------------------------------------------------------
def check_login(username: str, password_attempt: str) -> LoginResult:
    """
    Checks password_attempt against the full n=20 honeyset for username.

    Timing invariant: ALL 20 hashes are always evaluated — no short-circuit.
    This prevents timing attacks from revealing set density or real_index position.

    Returns:
      LoginResult('REAL',  user_id, None)        — real password matched
      LoginResult('HONEY', user_id, match_index) — honeyword matched
      LoginResult('FAILED', None, None)           — no match in set
    """
    conn = db_backend.connect()

    row = conn.execute(
        f"SELECT user_id, honeyset_salt FROM users WHERE username={PH}",
        (username,)
    ).fetchone()

    if not row:
        conn.close()
        return LoginResult('FAILED', None, None)

    user_id, honeyset_salt_hex = row
    honeyset_salt = bytes.fromhex(honeyset_salt_hex)

    # Fetch all 20 hashes ordered by position
    hash_rows = conn.execute(
        f"SELECT hash_index, pw_hash FROM honeysets WHERE user_id={PH} ORDER BY hash_index",
        (user_id,)
    ).fetchall()

    real_idx_row = conn.execute(
        f"SELECT real_idx FROM real_index WHERE user_id={PH}",
        (user_id,)
    ).fetchone()

    conn.close()

    if not hash_rows or not real_idx_row:
        return LoginResult('FAILED', None, None)

    real_idx = real_idx_row[0]
    attempt_hash = _derive_hash(password_attempt, honeyset_salt)

    # Constant-time full scan — no early exit
    match_index = None
    for pos, stored_hash in hash_rows:
        if secrets.compare_digest(attempt_hash, stored_hash):
            match_index = pos          # record but continue scanning

    if match_index is None:
        return LoginResult('FAILED', None, None)

    if match_index == real_idx:
        return LoginResult('REAL', user_id, None)
    else:
        return LoginResult('HONEY', user_id, match_index)


# ---------------------------------------------------------------------------
# Salt retrieval helper (used by app.py to pass salts to crypto_engine)
# ---------------------------------------------------------------------------
def get_user_salts(user_id: str) -> Optional[dict]:
    """
    Returns {'honeyset_salt': bytes, 'vault_salt': bytes} for a user_id.
    Returns None if user not found.
    """
    conn = db_backend.connect()
    row  = conn.execute(
        f"SELECT honeyset_salt, vault_salt FROM users WHERE user_id={PH}",
        (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        'honeyset_salt': bytes.fromhex(row[0]),
        'vault_salt':    bytes.fromhex(row[1]),
    }
