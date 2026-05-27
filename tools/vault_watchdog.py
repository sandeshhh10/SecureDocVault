"""
vault_watchdog.py — Phase 5: Self-Healing Vault Trigger
========================================================
Secure-Doc · A.N.T. Architecture

Implements the Architectural Invariant:
  "Auto-regenerate Honey Vault files from Enron dataset if deleted."

How it works:
  check_and_heal(user_id, password, honeyset_salt, high_value)
    Called on every /dashboard load for a HONEY session.
    If vault/decoy/<user_id>/ is missing or empty:
      → calls generate_decoy_document() for N files from enron_loader
      → XOR-encrypts each with the user's honeyset key
      → writes to vault/decoy/<user_id>/
      → logs a VAULT_HEALED event to intrusion_audit.log

    This is silent to the intruder — the dashboard simply renders
    normally with a fresh set of believable documents.

Threshold constants:
  MIN_FILES     — minimum expected file count; triggers heal if below
  STANDARD_N    — files to generate on standard heal
  HIGH_ALERT_N  — files to generate on high-alert heal (CONFIDENTIAL class)
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone

# ── Path bootstrap ─────────────────────────────────────────────────────────
_TOOLS = os.path.dirname(__file__)
_BASE  = os.path.join(_TOOLS, '..')
sys.path.insert(0, _TOOLS)

from crypto_engine import xor_encrypt
from enron_loader  import generate_decoy_document
from audit_logger  import LOG_PATH

# ── Paths ──────────────────────────────────────────────────────────────────
DECOY_VAULT = os.path.abspath(os.path.join(_BASE, 'vault', 'decoy'))

# ── Thresholds ─────────────────────────────────────────────────────────────
MIN_FILES    = 3    # below this triggers a heal
STANDARD_N   = 6   # files generated per standard heal
HIGH_ALERT_N = 6   # files generated per high-alert heal (all CONFIDENTIAL)


# ── Watchdog ───────────────────────────────────────────────────────────────
def check_and_heal(
    user_id:       str,
    password:      str,
    honeyset_salt: bytes,
    high_value:    bool = False
) -> bool:
    """
    Checks the decoy vault for user_id and heals it if depleted.

    Args:
        user_id       : the intruder's session user_id
        password      : their honeyword (used to re-derive XOR key)
        honeyset_salt : per-user salt
        high_value    : True → generate CONFIDENTIAL-class documents (Rule 4.2)

    Returns:
        True if a heal was performed, False if vault was healthy.
    """
    vault_dir = os.path.join(DECOY_VAULT, user_id)

    # Count existing non-hidden files
    existing = []
    if os.path.isdir(vault_dir):
        existing = [f for f in os.listdir(vault_dir)
                    if not f.startswith('.') and
                    os.path.isfile(os.path.join(vault_dir, f))]

    if len(existing) >= MIN_FILES:
        return False   # vault is healthy — nothing to do

    # ── Heal ──────────────────────────────────────────────────────────────
    os.makedirs(vault_dir, exist_ok=True)
    n = HIGH_ALERT_N if high_value else STANDARD_N

    written = []
    for _ in range(n):
        fmt = 'pdf' if high_value else 'random'
        fname, plaintext = generate_decoy_document(fmt=fmt)

        # Avoid filename collisions with existing files
        dest = os.path.join(vault_dir, fname)
        if os.path.exists(dest):
            base, ext = os.path.splitext(fname)
            fname = f"{base}_{uuid.uuid4().hex[:4]}{ext}"
            dest  = os.path.join(vault_dir, fname)

        encrypted = xor_encrypt(plaintext, password, honeyset_salt)
        with open(dest, 'wb') as f:
            f.write(encrypted)
        written.append(fname)

    # ── Log the heal event (append to intrusion_audit.log) ────────────────
    _log_heal_event(user_id, len(existing), written, high_value)

    return True


# ── Heal event logger ──────────────────────────────────────────────────────
def _log_heal_event(user_id: str, files_before: int,
                    files_written: list[str], high_value: bool) -> None:
    """
    Appends a VAULT_HEALED event to intrusion_audit.log.
    Separate from honey-login events; used for forensic completeness.
    """
    entry = {
        "log_id":         str(uuid.uuid4()),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "event_type":     "VAULT_HEALED",
        "user_id":        user_id,
        "files_before":   files_before,
        "files_written":  len(files_written),
        "asset_class":    "HIGH_VALUE" if high_value else "STANDARD",
        "filenames":      files_written,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
