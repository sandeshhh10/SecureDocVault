"""
check_honeywords.py — List every registered user and their honeyset size.
Runs against the SAME backend the app uses (Supabase Postgres when
SUPABASE_DB_URL is set, otherwise local SQLite) — so what you see here is what
the login arbiter actually checks against.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))
import db_backend
from db_backend import PH

print(f"Backend in use: {db_backend.backend_name()}\n")

conn = db_backend.connect()

users = conn.execute("SELECT username, user_id FROM users").fetchall()

if not users:
    print("No users registered in this backend.")

for username, user_id in users:
    count = conn.execute(
        f"SELECT COUNT(*) FROM honeysets WHERE user_id={PH}", (user_id,)
    ).fetchone()[0]
    print(f"User: {username} -> {count} honeywords in set")

conn.close()
