"""
app.py — Layer 1: Flask Application & Routing Arbiter
======================================================
Secure-Doc · Phase 3 · A.N.T. Architecture

Routes:
  GET  /           → redirect to /login
  GET  /login      → render login form
  POST /login      → authenticate via honey_checker → route to real/decoy vault
  GET  /register   → render registration form
  POST /register   → register new user via honey_checker
  GET  /dashboard  → serve vault file listing (real or decoy, indistinguishable)
  POST /logout     → clear session

Behavioral Invariants enforced here:
  Rule 1 — Honey Mode Silence: the HONEY branch is identical to REAL from the
            user's perspective. No leakage in response, headers, or timing.
  Rule 4.2 — Escalation: session_attempts counter lives in Flask session only.
             It increments on FAILED login, is read on HONEY login, then cleared.
"""

import os
import sys
import json
import uuid
import secrets
import sqlite3
from io import BytesIO
from datetime import datetime, timezone, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file)
from werkzeug.utils import secure_filename

# ── Local imports ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))
import db_backend
import account_lock
import log_analytics
import alerting
from honey_checker  import register_user, check_login, get_user_salts
from audit_logger   import log_honey_event
from honeyfile_gen  import populate_decoy_vault
from vault_watchdog import check_and_heal
from crypto_engine  import (
    xor_decrypt,
    aes_decrypt_with_key,
    aes_encrypt_with_key,
    derive_vault_key,
)

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECDOC_SECRET', os.urandom(32))

BASE_DIR    = os.path.dirname(__file__)
DB_PATH     = os.path.join(BASE_DIR, 'secure_doc.db')
REAL_VAULT  = os.path.join(BASE_DIR, 'vault', 'real')
DECOY_VAULT = os.path.join(BASE_DIR, 'vault', 'decoy')
LOG_PATH    = os.path.join(BASE_DIR, 'logs', 'intrusion_audit.log')

# Maximum file size accepted from any user (16 MB)
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

REAL_SESSION_TABLE = 'real_vault_sessions'

# File extensions permitted in the real vault
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'docx', 'doc', 'xlsx', 'xls',
    'csv', 'png', 'jpg', 'jpeg', 'md', 'eml'
}


def _allowed(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS


def _safe_vault_path(vault_root: str, user_id: str, filename: str) -> str | None:
    """
    Builds an absolute path inside vault_root/user_id/ and verifies it does
    not escape the vault via directory traversal (e.g. ../../etc/passwd).

    Returns the resolved path, or None if traversal is detected.
    """
    user_vault = os.path.realpath(os.path.join(vault_root, user_id))
    target     = os.path.realpath(os.path.join(user_vault, filename))

    # Ensure the resolved path is still inside the user's vault directory
    if not target.startswith(user_vault + os.sep) and target != user_vault:
        return None
    return target


def _phantom_log(event: str, extra: dict) -> None:
    """
    Appends a phantom operation event to intrusion_audit.log.
    Called only on HONEY sessions — never on real sessions.
    """
    entry = {
        "log_id":    str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event,
        "user_id":   session.get('user_id', 'unknown'),
        "username":  session.get('username', 'unknown'),
        "ip_address": request.headers.get('X-Forwarded-For',
                                          request.remote_addr or '0.0.0.0'),
        "user_agent": request.headers.get('User-Agent', ''),
        **extra,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


# ── Helpers ────────────────────────────────────────────────────────────────
def _vault_files(vault_dir: str, user_id: str) -> list[dict]:
    """
    Returns a list of file metadata dicts from a user's vault directory.
    Used identically for both real and decoy vaults — same response shape.
    """
    user_vault = os.path.join(vault_dir, user_id)
    if not os.path.isdir(user_vault):
        return []
    files = []
    for fname in sorted(os.listdir(user_vault)):
        fpath = os.path.join(user_vault, fname)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            size = stat.st_size
            size_str = f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"
            modified = datetime.fromtimestamp(stat.st_mtime).strftime('%d %b %Y')
            files.append({'name': fname, 'size': size_str, 'modified': modified})
    return files


def _format_display_size(size: int) -> str:
    return f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"


def _phantom_uploaded_files() -> list[dict]:
    files = []
    for item in session.get('phantom_uploaded', []):
        uploaded_at = item.get('uploaded_at', '')
        try:
            modified = datetime.fromisoformat(uploaded_at).strftime('%d %b %Y')
        except ValueError:
            modified = datetime.now(timezone.utc).strftime('%d %b %Y')

        files.append({
            'name': item.get('filename', 'unknown'),
            'size': _format_display_size(int(item.get('size', 0))),
            'modified': modified,
        })

    return files


def _client_ip() -> str:
    return request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0')


def _lock_message(seconds: int) -> str:
    """Human-friendly 'account locked for N minutes' message."""
    minutes = max(1, (seconds + 59) // 60)   # round up to whole minutes
    unit = 'minute' if minutes == 1 else 'minutes'
    return (f'Too many failed attempts. This account is locked for '
            f'{minutes} {unit}. Please try again later.')


def _log_security_event(event: str, extra: dict) -> None:
    """
    Appends a security event (e.g. ACCOUNT_LOCKED) to the real intrusion audit
    log, so it surfaces in the admin dashboard table and trend charts. Unlike
    _phantom_log this does not assume an active session — it is used on the
    login path where no user is signed in.
    """
    entry = {
        "log_id":     str(uuid.uuid4()),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "event_type": event,
        "ip_address": _client_ip(),
        "user_agent": request.headers.get('User-Agent', ''),
        "alert_level": "HIGH",
        **extra,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def _ensure_real_vault_session_table() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        f'''
        CREATE TABLE IF NOT EXISTS {REAL_SESSION_TABLE} (
            session_token TEXT PRIMARY KEY,
            user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            vault_key     BLOB NOT NULL,
            created_at    TEXT NOT NULL,
            expires_at    TEXT NOT NULL
        )
        '''
    )
    conn.execute(
        f'CREATE INDEX IF NOT EXISTS idx_{REAL_SESSION_TABLE}_user_id ON {REAL_SESSION_TABLE}(user_id)'
    )
    conn.commit()
    conn.close()


def _create_real_vault_session(user_id: str, vault_key: bytes) -> str:
    _ensure_real_vault_session_table()
    session_token = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=12)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        f'''
        INSERT INTO {REAL_SESSION_TABLE} (session_token, user_id, vault_key, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (session_token, user_id, vault_key, now.isoformat(), expires_at.isoformat())
    )
    conn.commit()
    conn.close()
    return session_token


def _get_real_vault_key(session_token: str) -> bytes | None:
    _ensure_real_vault_session_table()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        f'SELECT vault_key, expires_at FROM {REAL_SESSION_TABLE} WHERE session_token=?',
        (session_token,)
    ).fetchone()
    if not row:
        conn.close()
        return None

    vault_key, expires_at = row
    if expires_at and expires_at <= datetime.now(timezone.utc).isoformat():
        conn.execute(f'DELETE FROM {REAL_SESSION_TABLE} WHERE session_token=?', (session_token,))
        conn.commit()
        conn.close()
        return None

    conn.close()
    return vault_key


def _clear_real_vault_session(session_token: str) -> None:
    _ensure_real_vault_session_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f'DELETE FROM {REAL_SESSION_TABLE} WHERE session_token=?', (session_token,))
    conn.commit()
    conn.close()


def _active_real_vault_key() -> bytes | None:
    # The real-vault AES key is kept in the signed session cookie (client-side),
    # so it survives server restarts / ephemeral hosting (e.g. Render free tier),
    # where a local on-disk key store would be wiped between requests.
    hex_key = session.get('vault_key')
    return bytes.fromhex(hex_key) if hex_key else None


def _clear_all_real_vault_sessions() -> None:
    _ensure_real_vault_session_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f'DELETE FROM {REAL_SESSION_TABLE}')
    conn.commit()
    conn.close()


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # Send signed-in users to their vault; everyone else to the login page.
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/privacy')
def privacy():
    """Public privacy policy page (no authentication required)."""
    return render_template('privacy.html', logged_in=('user_id' in session))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=None, username='')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        return render_template('login.html',
                               error='Please enter both username and password.',
                               username=username)

    # Resolve the login OUTCOME first, then decide on lockout. Checking the
    # outcome before the lock lets us exempt HONEY entirely (Rule 1): an
    # intruder who matched a honeyword is never locked out, no matter how many
    # times they retry. Only genuine REAL access and outright FAILED attempts
    # are subject to the brute-force lock.
    result = check_login(username, password)

    # ── REAL LOGIN ──────────────────────────────────────────────────────────
    if result.outcome == 'REAL':
        # A correct password is still refused while the account is locked — the
        # lock is the whole point of the feature (standard account protection).
        locked, secs = account_lock.lock_status(username)
        if locked:
            return render_template('login.html',
                                   error=_lock_message(secs),
                                   username=username)

        # Genuine success clears the failed-attempt tally.
        account_lock.reset(username)

        salts = get_user_salts(result.user_id)
        if not salts:
            return render_template('login.html',
                                   error='Unable to load vault encryption context.',
                                   username=username)

        vault_key = derive_vault_key(password, salts['vault_salt'])

        session.clear()
        session['user_id']    = result.user_id
        session['username']   = username
        session['vault_mode'] = 'real'           # never sent to client
        # Store the derived AES key in the signed session cookie. It is signed
        # with SECDOC_SECRET (tamper-proof) and holds a derived key, never the
        # password. This keeps decryption working on restart-prone free hosting.
        session['vault_key']  = vault_key.hex()
        return redirect(url_for('dashboard'))

    # ── HONEY LOGIN ─────────────────────────────────────────────────────────
    # Deliberately exempt from the brute-force lock: we never call
    # account_lock.record_failure()/reset() here, so an intruder who keeps
    # entering a honeyword is kept engaged in the decoy vault indefinitely.
    elif result.outcome == 'HONEY':
        prior_failures = session.get('session_attempts', 0)
        high_alert     = prior_failures > 3   # Rule 4.2 threshold

        # Retrieve salts for decoy vault population
        salts = get_user_salts(result.user_id)

        # Populate decoy vault if empty (or on every high-alert login for freshness)
        vault_is_empty = db_backend.count_documents(result.user_id, 'decoy') == 0
        if vault_is_empty or high_alert:
            if salts:
                populate_decoy_vault(
                    user_id      = result.user_id,
                    password     = password,
                    honeyset_salt= salts['honeyset_salt'],
                    high_value   = high_alert   # Rule 4.2: CONFIDENTIAL templates on HIGH
                )

        # Log intrusion (Rule 4.2 escalation handled inside audit_logger)
        log_honey_event(
            username_attempted      = username,
            honeyword_index_matched = result.honey_index,
            ip_address              = _client_ip(),
            user_agent              = request.headers.get('User-Agent', ''),
            session_token_issued    = os.urandom(16).hex(),
            prior_failures          = prior_failures
        )

        # Respond: push a real-time alert (non-blocking; invisible to the
        # intruder). Best-effort — never affects the response they receive.
        alerting.send_alert(
            'HONEY_LOGIN_GRANTED',
            username    = username,
            ip          = _client_ip(),
            alert_level = 'HIGH' if high_alert else 'NORMAL',
            detail      = (f'Honeyword slot {result.honey_index} matched — '
                           f'intruder routed to the decoy vault.'),
        )

        # Issue a normal-looking session — indistinguishable from REAL
        session.clear()
        session['user_id']    = result.user_id
        session['username']   = username
        session['vault_mode'] = 'decoy'          # never sent to client
        session['honey_pw']   = password         # needed by watchdog for XOR re-keying
        session['high_alert'] = high_alert       # Rule 4.2 flag for watchdog
        session['phantom_hidden'] = []
        session['phantom_uploaded'] = []
        return redirect(url_for('dashboard'))

    # ── FAILED LOGIN ────────────────────────────────────────────────────────
    else:
        # Rule 4.2: increment in-session counter (never persisted; drives honey
        # escalation alert level only).
        session['session_attempts'] = session.get('session_attempts', 0) + 1

        # Persistent brute-force lockout: 5 failures → locked for 15 minutes.
        # HONEY never reaches this branch, so the honeypot is never locked.
        locked, secs = account_lock.record_failure(username)
        if locked:
            _log_security_event('ACCOUNT_LOCKED', {
                'username_attempted': username,
                'action': (f'Account locked for {account_lock.LOCK_MINUTES} minutes '
                           f'after {account_lock.MAX_FAILED} failed login attempts.'),
            })
            alerting.send_alert(
                'ACCOUNT_LOCKED',
                username    = username,
                ip          = _client_ip(),
                alert_level = 'HIGH',
                detail      = (f'{account_lock.MAX_FAILED} failed attempts — locked '
                               f'for {account_lock.LOCK_MINUTES} minutes.'),
            )
            return render_template('login.html',
                                   error=_lock_message(secs),
                                   username=username)

        return render_template('login.html',
                               error='Invalid username or password.',
                               username=username)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('login.html', error=None, username='',
                               register_mode=True)

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        return render_template('login.html',
                               error='Username and password are required.',
                               username=username, register_mode=True)
    if len(password) < 8:
        return render_template('login.html',
                               error='Password must be at least 8 characters.',
                               username=username, register_mode=True)

    try:
        register_user(username, password)
    except ValueError as e:
        return render_template('login.html', error=str(e), username=username, register_mode=True)

    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id    = session['user_id']
    username   = session['username']
    vault_mode = session.get('vault_mode', 'real')

    # Self-healing trigger (Phase 5): silently re-populate decoy vault if depleted
    if vault_mode == 'decoy':
        salts = get_user_salts(user_id)
        if salts:
            high_alert = session.get('high_alert', False)
            check_and_heal(
                user_id       = user_id,
                password      = session.get('honey_pw', ''),
                honeyset_salt = salts['honeyset_salt'],
                high_value    = high_alert
            )

    # Select vault — identical code path, only the vault_type differs
    vault_type = 'real' if vault_mode == 'real' else 'decoy'
    files      = db_backend.list_documents(user_id, vault_type)

    if vault_mode == 'decoy':
        hidden = set(session.get('phantom_hidden', []))
        files = [f for f in files if f['name'] not in hidden]
        files.extend(_phantom_uploaded_files())

    # Render identical template regardless of vault_mode
    return render_template('dashboard.html', username=username, files=files)


@app.route('/upload', methods=['POST'])
def upload():
    """
    Handles file uploads for both real and honey sessions.

    REAL SESSION:
      - Validates file extension against ALLOWED_EXTENSIONS whitelist.
      - Enforces MAX_UPLOAD_BYTES size limit.
      - Sanitises filename with werkzeug.secure_filename (strips path separators,
        null bytes, and other dangerous characters).
      - Resolves the final path with _safe_vault_path() to block directory traversal.
            - Encrypts the uploaded bytes with a server-side AES-256-GCM key before writing to vault/real/<user_id>/.

    HONEY SESSION — Phantom Upload:
      - Accepts the multipart request normally (no UI difference).
      - Reads and immediately discards the file stream — nothing is written to disk.
        This prevents an intruder from using the upload endpoint to plant malware.
      - Logs filename, declared size, and MIME type to intrusion_audit.log.
      - Returns the same success redirect as a real upload.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    vault_mode = session.get('vault_mode', 'real')
    user_id    = session['user_id']

    if 'file' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']

    if not file or file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('dashboard'))

    # ── HONEY SESSION — Phantom Upload ─────────────────────────────────────
    if vault_mode == 'decoy':
        # Drain and discard the stream — never touch the filesystem
        declared_name = file.filename or 'unknown'
        safe_name     = secure_filename(declared_name) or 'unknown'

        # Read in chunks to avoid loading a large malicious payload into memory
        total_bytes = 0
        chunk_size  = 65_536   # 64 KB chunks
        while True:
            chunk = file.stream.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                break   # stop reading — payload already discarded

        # Log the phantom attempt
        _phantom_log('PHANTOM_UPLOAD', {
            'declared_filename': declared_name,
            'sanitised_filename': safe_name,
            'declared_content_type': file.content_type or 'unknown',
            'bytes_received': total_bytes,
            'action': 'DISCARDED',
        })

        phantom_uploaded = session.get('phantom_uploaded', [])
        phantom_uploaded.append({
            'filename': safe_name,
            'size': total_bytes,
            'uploaded_at': datetime.now(timezone.utc).isoformat(),
        })
        session['phantom_uploaded'] = phantom_uploaded
        session.modified = True

        # Return identical success experience
        flash(f'"{safe_name}" uploaded successfully.', 'success')
        return redirect(url_for('dashboard'))

    # ── REAL SESSION — Genuine Upload ───────────────────────────────────────

    salts = get_user_salts(user_id)
    vault_key = _active_real_vault_key()
    if not salts or not vault_key:
        flash('Upload failed due to missing encryption context.', 'error')
        return redirect(url_for('dashboard'))

    # 1. Sanitise filename
    safe_name = secure_filename(file.filename)
    if not safe_name:
        flash('Invalid filename.', 'error')
        return redirect(url_for('dashboard'))

    # 2. Extension whitelist
    if not _allowed(safe_name):
        flash(f'File type not permitted. Allowed: {", ".join(sorted(ALLOWED_EXTENSIONS))}', 'error')
        return redirect(url_for('dashboard'))

    # 3. Read the upload into memory, enforcing the size limit as we go
    buffer = bytearray()
    while True:
        chunk = file.stream.read(65_536)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > MAX_UPLOAD_BYTES:
            flash(f'File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.', 'error')
            return redirect(url_for('dashboard'))

    # 4. Encrypt with the real-vault AES key, then persist the CIPHERTEXT via the
    #    document backend (Supabase Postgres, or the local vault when Supabase is
    #    not configured). Plaintext never reaches storage.
    try:
        blob   = aes_encrypt_with_key(bytes(buffer), vault_key)
        stored = db_backend.put_document(user_id, 'real', safe_name, blob)
    except Exception:
        flash('Upload failed due to a server error.', 'error')
        return redirect(url_for('dashboard'))

    if not stored:
        flash('Invalid file path.', 'error')
        return redirect(url_for('dashboard'))

    flash(f'"{safe_name}" uploaded successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete/<path:filename>', methods=['POST'])
def delete(filename: str):
    """
    Handles file deletion for both real and honey sessions.

    REAL SESSION:
      - Sanitises the filename and resolves the absolute path.
      - Blocks directory traversal via _safe_vault_path().
      - Permanently deletes the file from vault/real/<user_id>/.

    HONEY SESSION — Phantom Delete:
      - Does NOT touch vault/decoy/<user_id>/ — all files remain in place.
        The intruder will never notice: they just see the success message.
      - Logs the attempted filename to intrusion_audit.log.
      - Returns the same success redirect as a real delete.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    vault_mode = session.get('vault_mode', 'real')
    user_id    = session['user_id']

    # Sanitise the filename from the URL
    safe_name = secure_filename(filename)
    if not safe_name:
        flash('Invalid filename.', 'error')
        return redirect(url_for('dashboard'))

    # ── HONEY SESSION — Phantom Delete ─────────────────────────────────────
    if vault_mode == 'decoy':
        phantom_hidden = session.get('phantom_hidden', [])
        if safe_name not in phantom_hidden:
            phantom_hidden.append(safe_name)
        session['phantom_hidden'] = phantom_hidden
        session.modified = True

        _phantom_log('PHANTOM_DELETE', {
            'requested_filename': filename,
            'sanitised_filename': safe_name,
            'action': 'NO-OP — decoy vault untouched, file retained for deception',
        })

        # Identical success experience — intruder sees no difference
        flash(f'"{safe_name}" deleted successfully.', 'success')
        return redirect(url_for('dashboard'))

    # ── REAL SESSION — Genuine Delete ───────────────────────────────────────
    # Directory traversal is guarded inside db_backend for the filesystem path;
    # the Postgres path deletes by (user_id, vault_type, filename).
    try:
        deleted = db_backend.delete_document(user_id, 'real', safe_name)
    except Exception:
        flash('Delete failed due to a server error.', 'error')
        return redirect(url_for('dashboard'))

    if not deleted:
        flash(f'"{safe_name}" not found in your vault.', 'error')
        return redirect(url_for('dashboard'))

    flash(f'"{safe_name}" deleted successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/download/<path:filename>', methods=['GET'])
def download(filename: str):
    """
    Serves a file from the active vault.

    REAL SESSION:
      - Resolves the requested file inside vault/real/<user_id>/.
            - Decrypts the AES-256-GCM blob and streams the plaintext back as an attachment.

    HONEY SESSION:
      - Resolves the requested file inside vault/decoy/<user_id>/.
      - Logs the access as a phantom download while returning the decoy file.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    vault_mode = session.get('vault_mode', 'real')
    user_id    = session['user_id']
    safe_name  = secure_filename(filename)

    if not safe_name:
        flash('Invalid filename.', 'error')
        return redirect(url_for('dashboard'))

    # Read the stored (encrypted) bytes from the document backend — same place
    # uploads are written, so this works with Supabase and the local vault alike.
    vault_type = 'real' if vault_mode == 'real' else 'decoy'
    ciphertext = db_backend.get_document(user_id, vault_type, safe_name)

    if ciphertext is None:
        flash(f'"{safe_name}" not found in your vault.', 'error')
        return redirect(url_for('dashboard'))

    if vault_mode == 'decoy':
        salts = get_user_salts(user_id)
        if not salts:
            flash('Unable to access file.', 'error')
            return redirect(url_for('dashboard'))

        plaintext = xor_decrypt(ciphertext, session.get('honey_pw', ''), salts['honeyset_salt'])
        _phantom_log('PHANTOM_DOWNLOAD', {
            'requested_filename': filename,
            'sanitised_filename': safe_name,
            'size': len(plaintext),
            'action': 'DECRYPTED and returned to caller',
        })

        return send_file(BytesIO(plaintext), as_attachment=True, download_name=safe_name)

    # Real vault — decrypt with the AES key from the active session.
    vault_key = _active_real_vault_key()
    if not vault_key:
        flash('Unable to access file.', 'error')
        return redirect(url_for('dashboard'))

    try:
        plaintext = aes_decrypt_with_key(ciphertext, vault_key)
    except ValueError:
        flash('Unable to decrypt file (wrong key or corrupted data).', 'error')
        return redirect(url_for('dashboard'))

    return send_file(BytesIO(plaintext), as_attachment=True, download_name=safe_name)


@app.route('/logout', methods=['POST'])
def logout():
    # session.clear() drops the vault key (and everything else) from the cookie.
    session.clear()
    return redirect(url_for('login'))


# ════════════════════════════════════════════════════════════════════════════
# ADMIN — Honey-Protected Admin Dashboard
# ════════════════════════════════════════════════════════════════════════════
#
# Two passwords exist — only the admin knows which is real:
#   REAL_ADMIN_PASS  → real intrusion_audit.log (actual attack data)
#   HONEY_ADMIN_PASS → fake_clean_audit.log (boring routine entries)
#
# An intruder who finds the admin login and tries a weak password (admin123)
# is shown a clean, personalised log that convinces them nothing is wrong.
# The real log is never exposed.
# ────────────────────────────────────────────────────────────────────────────

REAL_ADMIN_PASS  = 'AdminStrict2026'
HONEY_ADMIN_PASS = 'admin123'

REAL_LOG_PATH  = os.path.join(BASE_DIR, 'logs', 'intrusion_audit.log')
FAKE_LOG_PATH  = os.path.join(BASE_DIR, 'logs', 'fake_clean_audit.log')

# ── Fake log generator ────────────────────────────────────────────────────

def _ensure_fake_log() -> None:
    """
    Generates fake_clean_audit.log if it does not exist.
    Entries are boring routine system events — deliberately unalarming.
    The username 'sandeshgc' appears throughout to convince an intruder
    they are viewing a real, personalised admin environment.
    """
    if os.path.isfile(FAKE_LOG_PATH):
        return

    os.makedirs(os.path.dirname(FAKE_LOG_PATH), exist_ok=True)

    # Fixed timestamps anchored to recent past — believable, not obviously fake
    from datetime import timedelta
    base_time = datetime.now(timezone.utc).replace(microsecond=0)

    routine_events = [
        (-2880, "SYSTEM_BOOT",       "sandeshgc", "System initialised normally. All services started."),
        (-2865, "BACKUP_SUCCESS",     "sandeshgc", "Scheduled backup completed. 1.2 GB archived to /backups/20260501.tar.gz."),
        (-2860, "SESSION_START",      "sandeshgc", "Admin session opened for sandeshgc from 192.168.1.4."),
        (-2845, "CONFIG_READ",        "sandeshgc", "Configuration file loaded. No changes detected since last boot."),
        (-2830, "SESSION_END",        "sandeshgc", "Admin session closed for sandeshgc. Duration: 14m 32s."),
        (-1440, "SYSTEM_HEALTHCHECK", "sandeshgc", "Scheduled health check passed. CPU 12%, MEM 38%, DISK 54%."),
        (-1438, "LOG_ROTATION",       "sandeshgc", "Log rotation completed. 3 old log files archived."),
        (-1420, "SESSION_START",      "sandeshgc", "Admin session opened for sandeshgc from 192.168.1.4."),
        (-1410, "VAULT_SYNC",         "sandeshgc", "Vault integrity check passed. 0 anomalies detected."),
        (-1405, "SESSION_REFRESH",    "sandeshgc", "Session refreshed for sandeshgc. Token extended by 30 minutes."),
        (-1395, "SESSION_END",        "sandeshgc", "Admin session closed for sandeshgc. Duration: 25m 01s."),
        ( -720, "SYSTEM_HEALTHCHECK", "sandeshgc", "Scheduled health check passed. CPU 9%, MEM 41%, DISK 54%."),
        ( -718, "BACKUP_SUCCESS",     "sandeshgc", "Incremental backup completed. 48 MB archived."),
        ( -700, "SESSION_START",      "sandeshgc", "Admin session opened for sandeshgc from 192.168.1.4."),
        ( -688, "CONFIG_UPDATED",     "sandeshgc", "Max upload limit updated to 16 MB by sandeshgc."),
        ( -680, "SESSION_END",        "sandeshgc", "Admin session closed for sandeshgc. Duration: 20m 14s."),
        (  -60, "SYSTEM_HEALTHCHECK", "sandeshgc", "Scheduled health check passed. CPU 11%, MEM 39%, DISK 55%."),
        (  -12, "SESSION_START",      "sandeshgc", "Admin session opened for sandeshgc from 192.168.1.4."),
        (   -8, "SESSION_REFRESH",    "sandeshgc", "Session refreshed for sandeshgc. Token extended by 30 minutes."),
        (   -2, "SESSION_END",        "sandeshgc", "Admin session closed for sandeshgc. Duration: 10m 03s."),
    ]

    with open(FAKE_LOG_PATH, 'w', encoding='utf-8') as f:
        for (offset_mins, event_type, actor, message) in routine_events:
            ts = (base_time + timedelta(minutes=offset_mins)).isoformat()
            entry = {
                "log_id":     str(uuid.uuid4()),
                "timestamp":  ts,
                "event_type": event_type,
                "actor":      actor,
                "message":    message,
                "alert_level":"NONE",
            }
            f.write(json.dumps(entry) + '\n')


def _read_log(path: str) -> list[dict]:
    """
    Reads a JSON Lines log file. Returns a list of parsed dicts,
    newest entries first. Skips malformed lines silently.
    """
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(entries))   # newest first


# ── Admin auth guard decorator ────────────────────────────────────────────

def _admin_required(fn):
    """Decorator: redirects to /admin/login if session role is not 'admin'."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return fn(*args, **kwargs)
    return wrapper


# ── Admin routes ──────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Honey-protected admin login.

    REAL_ADMIN_PASS  → role=admin, is_intruder=False  → real audit log
    HONEY_ADMIN_PASS → role=admin, is_intruder=True   → fake clean log
    Any other        → 401 error shown, attempt logged
    """
    if request.method == 'GET':
        return render_template('admin_login.html', error=None)

    password = request.form.get('password', '')

    if password == REAL_ADMIN_PASS:
        session.clear()
        session['role']        = 'admin'
        session['is_intruder'] = False
        return redirect(url_for('admin_dashboard'))

    elif password == HONEY_ADMIN_PASS:
        # Intruder used the honey password — log silently, grant access to fake data
        _phantom_log('HONEY_ADMIN_LOGIN', {
            'attempted_password_len': len(password),
            'action': 'Granted access to fake_clean_audit.log — real log concealed',
        })
        alerting.send_alert(
            'HONEY_ADMIN_LOGIN',
            ip          = _client_ip(),
            alert_level = 'HIGH',
            detail      = 'Intruder used the honey admin password — shown the fake log.',
        )
        session.clear()
        session['role']        = 'admin'
        session['is_intruder'] = True
        return redirect(url_for('admin_dashboard'))

    else:
        # Wrong password entirely — log and reject
        _phantom_log('ADMIN_LOGIN_FAILED', {
            'attempted_password_len': len(password),
            'action': 'Invalid admin password — access denied',
        })
        alerting.send_alert(
            'ADMIN_LOGIN_FAILED',
            ip          = _client_ip(),
            alert_level = 'NORMAL',
            detail      = 'Failed admin login attempt (wrong password).',
        )
        return render_template('admin_login.html',
                               error='Invalid admin password.'), 401


@app.route('/admin/dashboard')
@_admin_required
def admin_dashboard():
    """
    Honey-protected admin dashboard.

    Real admin  → reads intrusion_audit.log  (actual attack data)
    Honey admin → reads fake_clean_audit.log (routine system events)

    The template is identical — only the data differs.
    """
    is_intruder = session.get('is_intruder', True)   # default to safer path

    if is_intruder:
        _ensure_fake_log()
        entries   = _read_log(FAKE_LOG_PATH)
        log_label = 'System Audit Log'
    else:
        entries   = _read_log(REAL_LOG_PATH)
        log_label = 'Intrusion Audit Log'

    charts = log_analytics.build_chart_data(entries)

    return render_template(
        'admin_dashboard.html',
        entries        = entries,
        log_label      = log_label,
        is_intruder    = is_intruder,
        entry_count    = len(entries),
        charts         = charts,
        # Alerting status is shown only to the real admin — never to an intruder,
        # so the honey view stays indistinguishable (Rule 1).
        alert_enabled  = (not is_intruder) and alerting.enabled(),
        alert_channels = alerting.active_channels() if not is_intruder else [],
    )


@app.route('/admin/test-alert', methods=['POST'])
@_admin_required
def admin_test_alert():
    """Fires a test alert so the operator can verify their channel is wired up."""
    # Real admin only — an intruder on the fake log must not learn alerting exists.
    if session.get('is_intruder', True):
        return redirect(url_for('admin_dashboard'))

    if alerting.send_test_alert(triggered_by='admin'):
        flash('Test alert sent to the configured channel(s).', 'success')
    else:
        flash('No alert channel configured — set ALERT_TELEGRAM_*, ALERT_WEBHOOK_URL, or ALERT_SMTP_*.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
