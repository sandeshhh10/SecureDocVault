"""
db_backend.py — Storage Backend Selector
=========================================
Secure-Doc · A.N.T. Architecture

One switch, two backends — chosen at import time from the environment:

  SUPABASE_DB_URL set   →  Supabase Postgres (relational tables) + a `documents`
                           table holding encrypted blobs (via psycopg).
  SUPABASE_DB_URL unset →  Local SQLite (secure_doc.db) + the on-disk vault/
                           folders (original behaviour — kept as a fallback so
                           the project still runs and tests pass offline).

WHY A HYBRID, NOT SUPABASE AUTH:
  This project's login is a Juels & Rivest honeyword arbiter (see
  honey_checker.py) that must return REAL / HONEY / FAILED and silently route
  intruders to a decoy vault. A normal auth provider can only accept or reject,
  so Supabase Auth cannot express that. Supabase is therefore used purely as a
  *backend store*: Postgres for the honeyset tables, and a `documents` table for
  the already-encrypted file blobs. All encryption stays server-side, so
  Supabase only ever holds opaque ciphertext.

CREDENTIALS:
  Use the Postgres *connection string* from the Supabase dashboard
  (Settings → Database → Connection string → URI). It embeds your DB password
  and lets the Flask server write honeyset hashes that must never reach a
  browser. Do NOT use the anon/publishable key here — that key is for
  client-side access gated by RLS, which is the wrong trust model for a
  server that decides real-vs-decoy.

  Set it in a local .env file (auto-loaded below) or as an env var:
      SUPABASE_DB_URL=postgresql://postgres:<pw>@db.<ref>.supabase.co:5432/postgres
"""

import os
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SQLITE_PATH  = os.path.join(_BASE_DIR, 'secure_doc.db')
REAL_VAULT   = os.path.join(_BASE_DIR, 'vault', 'real')
DECOY_VAULT  = os.path.join(_BASE_DIR, 'vault', 'decoy')


# ---------------------------------------------------------------------------
# Minimal .env loader (no python-dotenv dependency — keep it lightweight)
# ---------------------------------------------------------------------------
def _load_dotenv() -> None:
    """Loads KEY=VALUE lines from <project>/.env into os.environ if not already set."""
    env_path = os.path.join(_BASE_DIR, '.env')
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                # Existing environment variables take precedence over the file.
                os.environ.setdefault(key, val)
    except OSError:
        pass


_load_dotenv()

# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
_DB_URL      = os.environ.get('SUPABASE_DB_URL', '').strip()
# Optional: supply the password separately (raw, no percent-encoding needed).
# Use this when the password contains URL-special characters like  # / + @ : ?
_DB_PASSWORD = os.environ.get('SUPABASE_DB_PASSWORD', '').strip()
USE_POSTGRES = bool(_DB_URL)

if USE_POSTGRES:
    import psycopg               # psycopg 3.x
    PH = '%s'                    # Postgres parameter placeholder
else:
    import sqlite3
    PH = '?'                     # SQLite parameter placeholder

VAULT_TYPES = ('real', 'decoy')


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
def connect():
    """
    Returns a DB-API 2.0 connection for the active backend.

    Both psycopg3 and sqlite3 expose Connection.execute(), .commit(), .close()
    and cursors with .fetchone()/.fetchall(), so callers can stay backend-neutral
    by using the PH placeholder and explicit .commit().
    """
    if USE_POSTGRES:
        if _DB_PASSWORD:
            return psycopg.connect(_DB_URL, password=_DB_PASSWORD)
        return psycopg.connect(_DB_URL)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def backend_name() -> str:
    return 'Supabase Postgres' if USE_POSTGRES else 'SQLite (local)'


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def _schema_statements() -> list[str]:
    blob_type = 'BYTEA' if USE_POSTGRES else 'BLOB'
    return [
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id       TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            created_at    TEXT NOT NULL,
            is_locked     INTEGER NOT NULL DEFAULT 0,
            vault_path    TEXT NOT NULL,
            honeyset_salt TEXT NOT NULL DEFAULT '',
            vault_salt    TEXT NOT NULL DEFAULT ''
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS honeysets (
            set_id      TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(user_id),
            hash_index  INTEGER NOT NULL,
            pw_hash     TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS real_index (
            user_id  TEXT PRIMARY KEY REFERENCES users(user_id),
            real_idx INTEGER NOT NULL
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS documents (
            doc_id      TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            vault_type  TEXT NOT NULL,
            filename    TEXT NOT NULL,
            content     {blob_type} NOT NULL,
            size_bytes  INTEGER NOT NULL,
            modified_at TEXT NOT NULL,
            UNIQUE (user_id, vault_type, filename)
        );
        """,
    ]


def init_schema() -> list[str]:
    """
    Creates all tables if absent. Safe to call on every startup.
    Returns the list of table names that exist afterwards.
    """
    conn = connect()
    try:
        for stmt in _schema_statements():
            conn.execute(stmt)
        conn.commit()
        if USE_POSTGRES:
            rows = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' ORDER BY table_name"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Display formatting helpers (kept identical to the original app._vault_files)
# ---------------------------------------------------------------------------
def _fmt_size(size: int) -> str:
    return f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"


def _fmt_date(dt: datetime) -> str:
    return dt.strftime('%d %b %Y')


def _vault_dir(vault_type: str) -> str:
    return REAL_VAULT if vault_type == 'real' else DECOY_VAULT


def _safe_user_path(vault_type: str, user_id: str, filename: str):
    """
    Resolves vault/<type>/<user_id>/<filename> and blocks directory traversal.
    Returns (user_dir, target_path) or (user_dir, None) if traversal detected.
    Filesystem backend only.
    """
    user_dir = os.path.realpath(os.path.join(_vault_dir(vault_type), user_id))
    target   = os.path.realpath(os.path.join(user_dir, filename))
    if not target.startswith(user_dir + os.sep) and target != user_dir:
        return user_dir, None
    return user_dir, target


# ---------------------------------------------------------------------------
# Document store — backend-neutral API
#   Both real and decoy vaults route through here so their code paths stay
#   identical (Rule 1 — Honey Mode Silence: no observable difference).
# ---------------------------------------------------------------------------
def list_documents(user_id: str, vault_type: str) -> list[dict]:
    """Returns [{'name','size','modified'}] sorted by filename, for one vault."""
    if USE_POSTGRES:
        conn = connect()
        try:
            rows = conn.execute(
                f"SELECT filename, size_bytes, modified_at FROM documents "
                f"WHERE user_id={PH} AND vault_type={PH} ORDER BY filename",
                (user_id, vault_type)
            ).fetchall()
        finally:
            conn.close()
        out = []
        for fname, size, modified_at in rows:
            try:
                dt = datetime.fromisoformat(modified_at)
            except (ValueError, TypeError):
                dt = datetime.now(timezone.utc)
            out.append({'name': fname, 'size': _fmt_size(size), 'modified': _fmt_date(dt)})
        return out

    # Filesystem backend
    user_dir = os.path.join(_vault_dir(vault_type), user_id)
    if not os.path.isdir(user_dir):
        return []
    files = []
    for fname in sorted(os.listdir(user_dir)):
        fpath = os.path.join(user_dir, fname)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            files.append({
                'name':     fname,
                'size':     _fmt_size(stat.st_size),
                'modified': _fmt_date(datetime.fromtimestamp(stat.st_mtime)),
            })
    return files


def count_documents(user_id: str, vault_type: str) -> int:
    if USE_POSTGRES:
        conn = connect()
        try:
            row = conn.execute(
                f"SELECT COUNT(*) FROM documents WHERE user_id={PH} AND vault_type={PH}",
                (user_id, vault_type)
            ).fetchone()
        finally:
            conn.close()
        return int(row[0]) if row else 0

    user_dir = os.path.join(_vault_dir(vault_type), user_id)
    if not os.path.isdir(user_dir):
        return 0
    return sum(1 for f in os.listdir(user_dir)
               if not f.startswith('.') and os.path.isfile(os.path.join(user_dir, f)))


def document_exists(user_id: str, vault_type: str, filename: str) -> bool:
    if USE_POSTGRES:
        conn = connect()
        try:
            row = conn.execute(
                f"SELECT 1 FROM documents WHERE user_id={PH} AND vault_type={PH} AND filename={PH}",
                (user_id, vault_type, filename)
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    _, target = _safe_user_path(vault_type, user_id, filename)
    return target is not None and os.path.isfile(target)


def put_document(user_id: str, vault_type: str, filename: str, content: bytes) -> bool:
    """
    Stores (or overwrites) an already-encrypted document blob.
    Returns False if a filesystem traversal is detected; True on success.
    Caller is responsible for sanitising `filename` (e.g. secure_filename).
    """
    if USE_POSTGRES:
        now = datetime.now(timezone.utc).isoformat()
        conn = connect()
        try:
            conn.execute(
                f"INSERT INTO documents "
                f"(doc_id, user_id, vault_type, filename, content, size_bytes, modified_at) "
                f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH}) "
                f"ON CONFLICT (user_id, vault_type, filename) DO UPDATE SET "
                f"content=excluded.content, size_bytes=excluded.size_bytes, "
                f"modified_at=excluded.modified_at",
                (str(uuid.uuid4()), user_id, vault_type, filename,
                 content, len(content), now)
            )
            conn.commit()
        finally:
            conn.close()
        return True

    # Filesystem backend — atomic write with traversal guard
    user_dir, target = _safe_user_path(vault_type, user_id, filename)
    if target is None:
        return False
    os.makedirs(user_dir, exist_ok=True)
    tmp = target + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(content)
    os.replace(tmp, target)
    return True


def get_document(user_id: str, vault_type: str, filename: str):
    """Returns the raw stored (encrypted) bytes, or None if not found."""
    if USE_POSTGRES:
        conn = connect()
        try:
            row = conn.execute(
                f"SELECT content FROM documents "
                f"WHERE user_id={PH} AND vault_type={PH} AND filename={PH}",
                (user_id, vault_type, filename)
            ).fetchone()
        finally:
            conn.close()
        return bytes(row[0]) if row else None

    _, target = _safe_user_path(vault_type, user_id, filename)
    if target is None or not os.path.isfile(target):
        return None
    with open(target, 'rb') as f:
        return f.read()


def delete_document(user_id: str, vault_type: str, filename: str) -> bool:
    """Deletes one document. Returns True if something was deleted."""
    if USE_POSTGRES:
        conn = connect()
        try:
            cur = conn.execute(
                f"DELETE FROM documents "
                f"WHERE user_id={PH} AND vault_type={PH} AND filename={PH}",
                (user_id, vault_type, filename)
            )
            deleted = cur.rowcount > 0
            conn.commit()
        finally:
            conn.close()
        return deleted

    _, target = _safe_user_path(vault_type, user_id, filename)
    if target is None or not os.path.isfile(target):
        return False
    os.remove(target)
    return True
