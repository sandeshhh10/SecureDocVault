"""
System Tests for Secure-Doc
Runs lightweight end-to-end checks:
 - create a test user in DB (with known decoys)
 - verify REAL and HONEY login outcomes
 - exercise AES and XOR encryption/decryption using user salts
 - clean up DB entries and vault dirs afterwards

Run: python system_tests.py
"""
import os
import sys
import sqlite3
import uuid
import secrets
import shutil
from datetime import datetime, timezone

# ensure tools are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

from honey_checker import _derive_hash, DB_PATH, HONEY_N
from crypto_engine import aes_encrypt, aes_decrypt, xor_encrypt, xor_decrypt

TEST_USERNAME = f"system_test_{uuid.uuid4().hex[:8]}"
REAL_PASSWORD = "SysTestReal!23"
DECOYS = ["DecoyAlpha1!", "DecoyBeta2!"]

def create_test_user(conn, username):
    user_id = str(uuid.uuid4())
    honeyset_salt = os.urandom(32)
    vault_salt = os.urandom(32)
    vault_path = f"vault/real/{user_id}/"

    real_hash = _derive_hash(REAL_PASSWORD, honeyset_salt)
    decoy_hashes = [_derive_hash(d, honeyset_salt) for d in DECOYS]
    full_set = [real_hash] + decoy_hashes
    indices = list(range(len(full_set)))
    rng = secrets.SystemRandom()
    rng.shuffle(indices)
    shuffled = [full_set[i] for i in indices]
    real_shuffled_idx = indices.index(0)

    now = datetime.now(timezone.utc).isoformat()

    try:
        with conn:
            conn.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                (user_id, username, now, 0, vault_path,
                 honeyset_salt.hex(), vault_salt.hex())
            )
            for pos, pw_hash in enumerate(shuffled):
                set_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO honeysets VALUES (?,?,?,?)",
                    (set_id, user_id, pos, pw_hash)
                )
            conn.execute(
                "INSERT INTO real_index VALUES (?,?)",
                (user_id, real_shuffled_idx)
            )
    except sqlite3.IntegrityError as e:
        raise

    # mkdir vault dirs
    base_dir = os.path.dirname(__file__)
    os.makedirs(os.path.join(base_dir, vault_path), exist_ok=True)
    os.makedirs(os.path.join(base_dir, f"vault/decoy/{user_id}/"), exist_ok=True)

    return user_id

def remove_test_user(conn, user_id):
    with conn:
        conn.execute("DELETE FROM honeysets WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM real_index WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE user_id=?", (user_id,))

def run():
    print("[system_tests] Using DB:", DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON;")

    print(f"[system_tests] Creating test user '{TEST_USERNAME}'")
    user_id = create_test_user(conn, TEST_USERNAME)
    print(f"[system_tests] Created user_id={user_id}")

    print("[system_tests] Running login checks via DB-backed honey checker")
    # import check_login from honey_checker
    from honey_checker import check_login, get_user_salts

    res_real = check_login(TEST_USERNAME, REAL_PASSWORD)
    print("[system_tests] Login with real password =>", res_real)

    # try a decoy that we inserted
    res_decoy = check_login(TEST_USERNAME, DECOYS[0])
    print("[system_tests] Login with decoy password =>", res_decoy)

    print("[system_tests] Retrieving salts and testing encryption roundtrips")
    salts = get_user_salts(user_id)
    if not salts:
        print("[system_tests] ERROR: could not retrieve user salts")
    else:
        hs = salts['honeyset_salt']
        vs = salts['vault_salt']
        sample = b"Integration test payload"

        # AES with real password
        ct = aes_encrypt(sample, REAL_PASSWORD, vs)
        pt = aes_decrypt(ct, REAL_PASSWORD, vs)
        print("[system_tests] AES roundtrip OK?", pt == sample)

        # XOR with decoy
        ct2 = xor_encrypt(sample, DECOYS[0], hs)
        pt2 = xor_decrypt(ct2, DECOYS[0], hs)
        print("[system_tests] XOR roundtrip OK?", pt2 == sample)

    # cleanup
    print("[system_tests] Cleaning up test user and vault dirs")
    remove_test_user(conn, user_id)
    base_dir = os.path.dirname(__file__)
    try:
        shutil.rmtree(os.path.join(base_dir, f"vault/real/{user_id}"))
    except Exception:
        pass
    try:
        shutil.rmtree(os.path.join(base_dir, f"vault/decoy/{user_id}"))
    except Exception:
        pass

    conn.close()
    print("[system_tests] Done")

if __name__ == '__main__':
    run()
