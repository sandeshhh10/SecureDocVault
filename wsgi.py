"""
wsgi.py — production entrypoint for a WSGI server (gunicorn, etc.)
=================================================================
Local development still uses `python run.py` (Flask's dev server).
In production, a real WSGI server imports the `app` object from here:

    gunicorn wsgi:app --bind 0.0.0.0:$PORT

Importing `app` also wires up the tools/ import path and reads config from
the environment. We then ensure the database schema exists (idempotent —
CREATE TABLE IF NOT EXISTS ...) so a fresh deploy is self-initialising.
"""

from app import app        # noqa: F401  (re-exported as the WSGI callable)
import db_backend

# Safe to run on every boot: creates tables only if they don't already exist.
db_backend.init_schema()

if __name__ == '__main__':
    # Allows `python wsgi.py` as a fallback; prefer gunicorn in production.
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
