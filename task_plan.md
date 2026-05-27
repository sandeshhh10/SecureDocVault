# task_plan.md — Secure-Doc Project Plan
_Status: ✅ ALL PHASES COMPLETE — B.L.A.S.T. BUILD FINISHED_

---

## B.L.A.S.T. Phase Checklist

### ✅ Phase 1: B — Blueprint (Vision & Logic) — COMPLETE
- [x] Answer 4 Discovery Questions
- [x] Define JSON Data Schema in gemini.md
- [x] Define Honeyword-Set Generation Algorithm (Chaffing-and-Winnowing, n=20)
- [x] Blueprint sign-off received — Phase 2 unlocked

### ✅ Phase 2: L — Link (Connectivity) — COMPLETE
- [x] Scaffold directory structure (vault/real, vault/decoy, data/enron, logs, tools, .tmp)
- [x] Verify SQLite database connections — secure_doc.db initialised, 3 tables confirmed, WAL mode ON
- [x] Verify vault directory read/write permissions — both vaults PASS, isolation PASS
- [x] Build Link probe scripts in tools/ (probe_db.py, probe_log.py, probe_vault.py)
- [x] Intrusion log path confirmed — logs/intrusion_audit.log append + JSON Lines PASS
- [⚠️] Enron seed data ABSENT — /data/enron/ is empty. Required before Phase 5 (Trigger). Non-blocking for Phases 3–4.

### ✅ Phase 3: A — Architect (A.N.T. 3-Layer Build) — COMPLETE
- [x] Layer 3: crypto_engine.py — XOR (Honey Vault) + AES-256-GCM (Real Vault), unified PBKDF2 KDF
- [x] Layer 2: honey_checker.py — Chaffing-and-Winnowing registration + constant-time login arbiter
- [x] Layer 2: audit_logger.py — Rule 4.2 escalation-aware append-only JSON Lines log writer
- [x] Layer 1: app.py — Flask routing arbiter, session management, vault_mode isolation
- [x] Layer 1: login.html + dashboard.html — indistinguishable UI for real and decoy sessions

### ✅ Phase 4: S — Stylize (Refinement & UI) — COMPLETE
- [x] Refined login.html — terminal-luxury aesthetic (Syne + DM Mono, grid bg, scanlines, animated card)
- [x] Refined dashboard.html — sticky topbar, stats row, sortable file table, cipher footer
- [x] honeyfile_gen.py — 8 standard Enron templates + 6 CONFIDENTIAL high-alert templates
- [x] Rule 4.2 wired end-to-end: high_alert flag → CONFIDENTIAL asset class → HIGH log entry
- [x] app.py patched: register_mode variable fix, honeyfile_gen integrated into honey login path
- [x] Decoy vault auto-populates on first honey login; refreshes on every HIGH-ALERT login

### ✅ Phase 5: T — Trigger (Deployment & Defense) — COMPLETE
- [x] enron_loader.py — parses refined_enron.json, renders .txt + .pdf decoy reports
- [x] vault_watchdog.py — detects depleted vault, auto-heals silently on every /dashboard load
- [x] VAULT_HEALED events logged to intrusion_audit.log (forensic completeness)
- [x] High-alert heal path: PDF-only + CONFIDENTIAL supplements (Rule 4.2)
- [x] Watchdog skips heal when vault is healthy (MIN_FILES threshold guard)
- [x] honeyfile_gen.py upgraded: enron_loader as primary source, embedded templates as fallback
- [x] app.py: honey_pw + high_alert stored in session for watchdog; vault_watchdog wired into /dashboard
- [x] requirements.txt — pinned dependency manifest (flask, pycryptodome, reportlab)
- [x] run.py — hardened startup: pre-flight checks, DB init, crypto self-test, Flask launch
- [x] Enron corpus seeded: data/enron/refined_enron.json (6 records, Phase 2 advisory resolved)

---

## Honeyword-Set Generation Algorithm (PENDING APPROVAL)

### Parameters
- `n = 20` (1 real password + 19 decoys per user)
- Method: **Chaffing-and-Winnowing** (Juels & Rivest model)

### Algorithm Steps
```
ON REGISTRATION(username, real_password):

1. Hash real_password → real_hash (bcrypt, cost=12)
2. Generate 19 decoy passwords via:
   a. Sample random base words from a curated wordlist
   b. Apply random leet-speak / digit-append / symbol mutations
      to match plausible password patterns
   c. Hash each decoy → decoy_hash (bcrypt, cost=12)
3. Assemble full_set = [real_hash] + [decoy_hash × 19]
4. Shuffle full_set using secrets.SystemRandom()
5. Record real_index = shuffled position of real_hash
6. Store:
   - full_set hashes → honeysets table (secure_doc.db)
   - real_index → isolated real_index table (separate hardened record)
7. Derive XOR key and AES-256 key from real_password (see gemini.md)
8. Encrypt user files:
   - Real files → AES-256-GCM → vault/real/<user_id>/
   - Seed decoy files from Enron dataset → XOR-encrypt → vault/decoy/<user_id>/
```

### Login Checker Logic
```
ON LOGIN(username, password_attempt):

1. Retrieve full_set for username
2. bcrypt.checkpw(password_attempt, each hash in full_set)
3. IF no match → LOGIN FAILED (standard rejection)
4. IF match at index i:
   a. Retrieve real_index for username
   b. IF i == real_index → REAL LOGIN → serve vault/real/
   c. IF i != real_index → HONEY LOGIN:
      - Issue normal-looking session token
      - Log to intruder_log.db (isolated)
      - Serve vault/decoy/ ← NEVER reveal this to user
```

1. Build a deception-based security vault with cryptographic integrity.
2. Ensure real/decoy vaults are strictly isolated at the filesystem level.
3. Never reveal "Honey Mode" to a user — behavioral invariant.
4. All intermediate operations use .tmp/ as workbench.

---

## ✅ Post-Build Addition: Honey-Protected Admin Dashboard
- [x] /admin/login — dual-password auth (real vs. honey), wrong password 401 + logged
- [x] /admin/dashboard — _admin_required guard, data path forks on is_intruder flag
- [x] _ensure_fake_log() — auto-generates fake_clean_audit.log on first honey login
- [x] fake_clean_audit.log — 20 routine entries, all attributed to sandeshgc
- [x] admin_login.html + admin_dashboard.html — identical template, data-driven only
- [x] Stats strip: Total Entries, Honey Logins, High Alerts, Phantom Ops, Vault Heals
