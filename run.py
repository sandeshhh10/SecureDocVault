"""
run.py — Secure-Doc Startup Script
====================================
Pre-flight checks → DB initialisation → Flask launch.

Usage:
    python3 run.py

Environment variables:
    SECDOC_SECRET   — Flask secret key (recommended in production)
                      Falls back to a fresh os.urandom(32) each restart
                      (invalidates existing sessions on restart — acceptable
                       for academic deployment).
    SECDOC_PORT     — Port to bind (default: 5000)
    SECDOC_HOST     — Host to bind (default: 127.0.0.1)
"""

import os
import sys
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'tools'))

# ── ANSI helpers ──────────────────────────────────────────────────────────
G  = '\033[32m';  Y = '\033[33m';  R = '\033[31m'
B  = '\033[34m';  W = '\033[0m';   BOLD = '\033[1m'
OK = f'{G}✓{W}'; WN = f'{Y}⚠{W}'; ER = f'{R}✗{W}'

def _hdr(msg): print(f'\n{BOLD}{B}▸ {msg}{W}')
def _ok(msg):  print(f'  {OK}  {msg}')
def _warn(msg):print(f'  {WN}  {Y}{msg}{W}')
def _err(msg): print(f'  {ER}  {R}{msg}{W}'); sys.exit(1)

# ── Pre-flight checks ─────────────────────────────────────────────────────

_hdr('Secure-Doc — Pre-flight')

# 1. Python version
if sys.version_info < (3, 10):
    _err(f'Python 3.10+ required (found {sys.version_info.major}.{sys.version_info.minor})')
_ok(f'Python {sys.version_info.major}.{sys.version_info.minor}')

# 2. Dependencies
_deps = {'flask': 'Flask', 'reportlab': 'reportlab'}
for mod, pkg in _deps.items():
    try:
        __import__(mod)
        _ok(f'{pkg}')
    except ImportError:
        _err(f'{pkg} not installed — run: pip install -r requirements.txt')

# 3. Directory structure
_dirs = ['vault/real', 'vault/decoy', 'data/enron', 'logs', 'tools', '.tmp']
for d in _dirs:
    path = os.path.join(BASE_DIR, d)
    os.makedirs(path, exist_ok=True)
_ok('Directory structure intact')

# 4. Enron corpus
enron_json = os.path.join(BASE_DIR, 'data', 'enron', 'refined_enron.json')
if os.path.isfile(enron_json):
    import json
    with open(enron_json) as f:
        records = json.load(f)
    _ok(f'Enron corpus — {len(records)} records loaded from refined_enron.json')
else:
    _warn('refined_enron.json not found — honeyfile generator will use embedded templates')

# 5. Database
_hdr('Database Initialisation')
try:
    import db_backend
except Exception as e:
    _err(f'Could not load storage backend: {e}')

if db_backend.USE_POSTGRES:
    try:
        import psycopg  # noqa: F401
    except ImportError:
        _err('SUPABASE_DB_URL is set but psycopg is not installed — '
             'run: pip install "psycopg[binary]"')

_ok(f'Storage backend: {db_backend.backend_name()}')
try:
    tables = db_backend.init_schema()
    _ok(f'Schema ready — tables: {", ".join(tables)}')
except Exception as e:
    _err(f'Database init failed: {e}')

# 6. Log file
LOG_PATH = os.path.join(BASE_DIR, 'logs', 'intrusion_audit.log')
try:
    with open(LOG_PATH, 'a') as _f:
        pass
    _ok(f'intrusion_audit.log — append-only, ready')
except OSError as e:
    _err(f'Cannot write to log file: {e}')

# 7. Crypto self-test
_hdr('Cryptographic Self-Test')
try:
    from crypto_engine import aes_encrypt, aes_decrypt, xor_encrypt, xor_decrypt
    _salt = os.urandom(32)
    _pt   = b'self-test payload'
    assert aes_decrypt(aes_encrypt(_pt, 'pw', _salt), 'pw', _salt) == _pt
    assert xor_decrypt(xor_encrypt(_pt, 'pw', _salt), 'pw', _salt) == _pt
    _ok('AES-256-CBC + HMAC-SHA256 round-trip: PASS')
    _ok('XOR round-trip:                       PASS')
except Exception as e:
    _err(f'Crypto self-test failed: {e}')

# ── Launch ────────────────────────────────────────────────────────────────
_hdr('Launching Flask Application')

host   = os.environ.get('SECDOC_HOST', '127.0.0.1')
port   = int(os.environ.get('SECDOC_PORT', 5000))
secret = os.environ.get('SECDOC_SECRET', None)

if not secret:
    _warn('SECDOC_SECRET not set — using ephemeral key (sessions reset on restart)')

print(f'\n  {BOLD}SecureDoc is running at http://{host}:{port}{W}')
print(f'  Press Ctrl+C to stop.\n')

import app as secdoc_app
if secret:
    secdoc_app.app.secret_key = secret.encode()
secdoc_app.app.run(debug=False, host=host, port=port)
