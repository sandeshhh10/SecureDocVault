"""
Phase 2 Link Probe: logs/intrusion_audit.log
Creates the log file, verifies append-only write, and validates JSON Lines format.
"""

import json
import os
import uuid
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'intrusion_audit.log')

def probe_log():
    # Write a clearly-marked probe entry in append mode
    probe_entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username_attempted": "__PROBE__",
        "honeyword_index_matched": -1,
        "ip_address": "127.0.0.1",
        "user_agent": "LinkProbe/1.0",
        "session_token_issued": "PROBE_TOKEN",
        "action_taken": "PROBE_ONLY — NOT A REAL INTRUSION EVENT"
    }

    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(probe_entry) + '\n')

    # Verify the last line is valid JSON
    with open(LOG_PATH, 'r') as f:
        lines = f.readlines()
    last = json.loads(lines[-1])

    return last['log_id'] == probe_entry['log_id']

if __name__ == '__main__':
    ok = probe_log()
    print(f"[LOG PROBE] intrusion_audit.log path: {os.path.abspath(LOG_PATH)}")
    print(f"[LOG PROBE] Append + JSON Lines read-back: {'PASS' if ok else 'FAIL'}")
