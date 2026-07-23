"""
test_honeyword.py — Demo helper: plant a known honeyword on an account
======================================================================
Overwrites ONE decoy slot of a user's honeyset with a password you choose, so
you can log in with that password and be silently routed to the DECOY vault
(a HONEY login — indistinguishable from the real vault).

IMPORTANT — it runs against the SAME backend the app uses (via db_backend):
  • Supabase Postgres when SUPABASE_DB_URL is set (see .env), else
  • local SQLite (secure_doc.db).
Planting a honeyword into the wrong database is exactly why a demo can look
like "there is no routing": the app checks one DB, the script wrote to another.

Usage:
    python test_honeyword.py [username] [honeyword]
Defaults:
    username  = kamal
    honeyword = TestHoney_XYZ789!
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))
import db_backend
from db_backend import PH
import honey_checker   # reuse the app's exact PBKDF2 params — no drift

USERNAME  = sys.argv[1] if len(sys.argv) > 1 else 'kamal'
HONEYWORD = sys.argv[2] if len(sys.argv) > 2 else 'TestHoney_XYZ789!'

print(f"Backend in use: {db_backend.backend_name()}")

conn = db_backend.connect()

row = conn.execute(
    f"SELECT user_id, honeyset_salt FROM users WHERE username={PH}",
    (USERNAME,)
).fetchone()

if not row:
    print(f"\n[X] User '{USERNAME}' not found in {db_backend.backend_name()}.")
    print("  Register the account first (web UI), and make sure you run this")
    print("  script against the SAME backend the app uses (check SUPABASE_DB_URL).")
    conn.close()
    sys.exit(1)

user_id, salt_hex = row
salt = bytes.fromhex(salt_hex)

# Hash the chosen honeyword with the app's own KDF, so login recognises it.
test_hash = honey_checker._derive_hash(HONEYWORD, salt)

real_idx = conn.execute(
    f"SELECT real_idx FROM real_index WHERE user_id={PH}", (user_id,)
).fetchone()[0]

positions = [
    r[0] for r in conn.execute(
        f"SELECT hash_index FROM honeysets WHERE user_id={PH} ORDER BY hash_index",
        (user_id,)
    ).fetchall()
]

decoy_positions = [p for p in positions if p != real_idx]
if not decoy_positions:
    print("[X] No decoy positions found for this user.")
    conn.close()
    sys.exit(1)

target_position = decoy_positions[0]

conn.execute(
    f"UPDATE honeysets SET pw_hash={PH} WHERE user_id={PH} AND hash_index={PH}",
    (test_hash, user_id, target_position)
)
conn.commit()
conn.close()

print("\n[OK] Honeyword planted:")
print(f"    Username : {USERNAME}")
print(f"    Password : {HONEYWORD}")
print(f"    Slot     : {target_position}  (decoy - real slot is {real_idx})")
print("\nLog in with that username + password -> you are served the DECOY vault")
print("(a HONEY login). The attempt is recorded in the intrusion audit log.")
