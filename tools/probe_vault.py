"""
Phase 2 Link Probe: Vault R/W Isolation + Enron Seed Check
Verifies real/decoy vault directories are writable and isolated.
Reports Enron dataset status.
"""

import os
import tempfile

BASE = os.path.join(os.path.dirname(__file__), '..')
VAULT_REAL  = os.path.abspath(os.path.join(BASE, 'vault', 'real'))
VAULT_DECOY = os.path.abspath(os.path.join(BASE, 'vault', 'decoy'))
ENRON_DIR   = os.path.abspath(os.path.join(BASE, 'data', 'enron'))

def check_rw(path, label):
    try:
        tf = tempfile.NamedTemporaryFile(dir=path, delete=True)
        tf.close()
        return f"[VAULT PROBE] {label}: READ/WRITE OK  ({path})"
    except Exception as e:
        return f"[VAULT PROBE] {label}: FAIL — {e}"

def check_isolation():
    # Confirm the two vault paths share no common sub-path beyond the base
    real_parts  = set(VAULT_REAL.split(os.sep))
    decoy_parts = set(VAULT_DECOY.split(os.sep))
    shared = real_parts & decoy_parts
    # Expected shared: root + 'secure_doc' + 'vault' — NOT 'real'/'decoy'
    unexpected = shared - {'', 'home', 'claude', 'secure_doc', 'vault'}
    if unexpected:
        return f"[VAULT PROBE] Isolation check: FAIL — unexpected shared segments: {unexpected}"
    return "[VAULT PROBE] Isolation check: PASS — real/decoy paths are fully separated"

def check_enron():
    files = []
    if os.path.isdir(ENRON_DIR):
        files = [f for f in os.listdir(ENRON_DIR) if not f.startswith('.')]
    if files:
        return f"[ENRON PROBE] Seed data PRESENT — {len(files)} items found in {ENRON_DIR}"
    return (
        f"[ENRON PROBE] Seed data ABSENT — {ENRON_DIR} is empty.\n"
        f"             ACTION REQUIRED before Phase 5: populate /data/enron/ with Enron corpus.\n"
        f"             Suggested source: https://www.cs.cmu.edu/~enron/ (Enron Email Dataset)"
    )

if __name__ == '__main__':
    print(check_rw(VAULT_REAL,  'vault/real '))
    print(check_rw(VAULT_DECOY, 'vault/decoy'))
    print(check_isolation())
    print(check_enron())
