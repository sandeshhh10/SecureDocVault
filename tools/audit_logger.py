"""
audit_logger.py — Layer 2: Intrusion Audit Logger
==================================================
Secure-Doc · Phase 3 · A.N.T. Architecture

Writes intrusion events to logs/intrusion_audit.log as JSON Lines.
Implements Rule 4.2 (Escalation): injects alert_level and prior_failures
fields when session_attempts > 3 prior to a honeyword match.

Behavioral Rule 1 (Honey Mode Silence) is enforced here:
  - This module is ONLY called from the Honey Login path.
  - It is never called on Real Login.
  - It must never surface any field to the Flask response layer.
"""

import json
import os
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Path — resolved relative to this file's location (tools/ → logs/)
# ---------------------------------------------------------------------------
_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'intrusion_audit.log')
LOG_PATH  = os.path.abspath(_LOG_PATH)


# ---------------------------------------------------------------------------
# Alert thresholds (Rule 4.2)
# ---------------------------------------------------------------------------
HIGH_ALERT_THRESHOLD = 3   # prior_failures > this value triggers HIGH-ALERT


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def log_honey_event(
    username_attempted: str,
    honeyword_index_matched: int,
    ip_address: str,
    user_agent: str,
    session_token_issued: str,
    prior_failures: int = 0
) -> None:
    """
    Appends a single intrusion event to intrusion_audit.log.

    Rule 4.2 logic:
      - If prior_failures > HIGH_ALERT_THRESHOLD:
          alert_level = "HIGH", prior_failures field included in record.
      - Otherwise:
          alert_level = "NORMAL", prior_failures field omitted.

    Args:
        username_attempted      : the username string from the login form
        honeyword_index_matched : position (0–19) in the honeyset that matched
        ip_address              : client IP from Flask request
        user_agent              : client User-Agent header
        session_token_issued    : the Flask session token given to the intruder
        prior_failures          : number of failed attempts before this honey match
    """
    entry = {
        "log_id":                 str(uuid.uuid4()),
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "username_attempted":     username_attempted,
        "honeyword_index_matched": honeyword_index_matched,
        "ip_address":             ip_address,
        "user_agent":             user_agent,
        "session_token_issued":   session_token_issued,
        "action_taken":           "HONEY_LOGIN_GRANTED",
        "alert_level":            "NORMAL",
    }

    # Rule 4.2 — escalation fields
    if prior_failures > HIGH_ALERT_THRESHOLD:
        entry["alert_level"]    = "HIGH"
        entry["prior_failures"] = prior_failures

    _append(entry)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------
def _append(entry: dict) -> None:
    """
    Opens the log file in append-only mode and writes one JSON Line.
    Creates the file if it does not exist.
    Raises OSError if the log directory is not writable (surfaces to caller).
    """
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
