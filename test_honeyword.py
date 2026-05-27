import sqlite3
import hashlib
import uuid
import random

conn = sqlite3.connect('secure_doc.db')

# Get your user 
row = conn.execute(
    "SELECT user_id, honeyset_salt FROM users WHERE username='kamal'"
).fetchone()

if not row:
    print("User not found. Create an account first via the web UI.")
    conn.close()
    exit(1)

user_id, salt_hex = row
salt = bytes.fromhex(salt_hex)

# Generate a test honeyword
test_honeyword = "TestHoney_XYZ789!"

# Hash it using the same PBKDF2 method
test_hash = hashlib.pbkdf2_hmac(
    'sha256',
    test_honeyword.encode('utf-8'),
    salt,
    200_000,
    dklen=32
).hex()

# Get the real index
real_idx = conn.execute(
    "SELECT real_idx FROM real_index WHERE user_id=?", (user_id,)
).fetchone()[0]

# Get all current positions
all_positions = [
    row[0] for row in conn.execute(
        "SELECT hash_index FROM honeysets WHERE user_id=? ORDER BY hash_index", (user_id,)
    ).fetchall()
]

# Find a decoy position (any position that is NOT the real_index)
decoy_positions = [p for p in all_positions if p != real_idx]

if not decoy_positions:
    print("Error: No decoy positions found!")
    conn.close()
    exit(1)

# Pick one decoy position to overwrite
target_position = decoy_positions[0]

# Update that position with the test honeyword
conn.execute(
    "UPDATE honeysets SET pw_hash=? WHERE user_id=? AND hash_index=?",
    (test_hash, user_id, target_position)
)
conn.commit()
conn.close()

print(f"✓ Test honeyword created:")
print(f"  Username:     kamal")
print(f"  Password:     TestHoney_XYZ789!")
print(f"  Position:     {target_position} (decoy, not the real index {real_idx})")
print(f"\nNow log in with this password on http://127.0.0.1:5000")
print(f"You will be served the DECOY vault (indistinguishable from real).")