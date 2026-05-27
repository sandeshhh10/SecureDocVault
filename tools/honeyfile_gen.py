"""
honeyfile_gen.py — Phase 4: Honeyfile Generator
================================================
Secure-Doc · A.N.T. Architecture

Generates believable decoy documents for vault/decoy/<user_id>/.

Two asset classes (Rule 4.2):
  Standard  — realistic Enron-style internal email threads (.eml, .txt)
  High-Value — CONFIDENTIAL-stamped memos, deal sheets, legal notices (.txt, .eml)
               Used when alert_level == 'HIGH' (prior_failures > 3)

Source priority:
  1. Live Enron corpus at /data/enron/ (Phase 5 — when seeded)
  2. Embedded template library (Phase 4 — always available as fallback)

All generated files are XOR-encrypted via crypto_engine before being written
to the decoy vault. The function interface is identical regardless of asset class.
"""

import os
import random
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Literal

# ── Paths ──────────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.join(os.path.dirname(__file__), '..')
DECOY_VAULT = os.path.abspath(os.path.join(_BASE_DIR, 'vault', 'decoy'))
ENRON_DIR   = os.path.abspath(os.path.join(_BASE_DIR, 'data', 'enron'))

# ── Config ─────────────────────────────────────────────────────────────────
STANDARD_COUNT    = 8    # files generated per standard session
HIGH_VALUE_COUNT  = 6    # files generated per high-alert session


# ── Name pools ─────────────────────────────────────────────────────────────
_FIRST = ["Mark", "Sara", "James", "Diane", "Kevin", "Laura", "Eric",
          "Tanya", "Robert", "Michelle", "David", "Patricia", "Brian",
          "Angela", "Scott", "Linda", "Jeff", "Carol", "Tom", "Nancy"]
_LAST  = ["Henderson", "Watts", "Collins", "Morgan", "Hayes", "Porter",
          "Simmons", "Reed", "Bailey", "Bell", "Cooper", "Rivera",
          "Foster", "Jenkins", "Patterson", "Howard", "Ward", "Cox"]
_DEPTS = ["Risk Management", "Corporate Finance", "Legal", "Compliance",
          "Strategic Planning", "Treasury", "Investor Relations", "Audit"]
_TICKERS = ["ENE", "DYN", "CMS", "WPS", "AEP", "EXC", "SO", "PCG"]


def _name() -> str:
    return f"{random.choice(_FIRST)} {random.choice(_LAST)}"

def _email(name: str) -> str:
    first, last = name.lower().split()
    return f"{first}.{last}@enron.com"

def _date(days_ago: int = 0) -> str:
    d = datetime(2001, 11, 30) - timedelta(days=days_ago)
    return d.strftime("%a, %d %b %Y %H:%M:%S -0600")

def _dept() -> str:
    return random.choice(_DEPTS)


# ── Standard asset templates ────────────────────────────────────────────────

def _gen_standard_email() -> tuple[str, str]:
    """Returns (filename, content) for a plausible internal email thread."""
    sender    = _name()
    recipient = _name()
    days_ago  = random.randint(3, 180)
    subject_pool = [
        "Re: Q3 Pipeline Update",
        "FWD: Counterparty Exposure — Action Required",
        "Weekly Position Summary",
        "Re: Gas Nominations — Nov Schedule",
        "Budget Variance Review — October",
        "Re: Hedging Strategy Discussion",
        "Meeting Notes — Risk Committee",
        "FW: Credit Limit Approval",
        "Re: Contract Renewal — [counterparty]",
        "Daily P&L Snapshot",
    ]
    subject = random.choice(subject_pool)
    body_pool = [
        f"Thanks for the update. I've reviewed the numbers and I think we're in reasonable shape on the {_ticker()} position. Let me know if you need anything else before EOD.",
        f"Following up on our call earlier — I've forwarded the exposure report to {_name()} in {_dept()}. She'll have comments by Thursday.",
        f"Please see the attached for the revised schedule. We need sign-off from Legal before we can proceed with the nomination.",
        f"The variance is largely explained by the basis differential in the Southwest. I'll have a full write-up for the Monday call.",
        f"Confirmed. I've updated the model with the new curve and the numbers look better. Still watching the spread closely.",
        f"Quick note: the weekly summary is attached. Overall exposure is within limits but we're getting close on the {_dept()} book.",
        f"I talked to {_name()} about this yesterday and he agrees we should bring it to the committee next week. Can you prepare a one-pager?",
    ]
    body = random.choice(body_pool)
    content = (
        f"From: {sender} <{_email(sender)}>\n"
        f"To: {recipient} <{_email(recipient)}>\n"
        f"Date: {_date(days_ago)}\n"
        f"Subject: {subject}\n"
        f"X-Mailer: Lotus Notes 5.0\n\n"
        f"{body}\n\n"
        f"--\n{sender}\n{_dept()}\nEnron Corp.\n"
        f"Tel: +1 713 853 {random.randint(1000,9999)}\n"
    )
    fname = f"{subject.replace('Re: ','').replace('FWD: ','').replace('FW: ','')[:32].strip().replace(' ','_')}_"
    fname += f"{datetime(2001,11,30)-timedelta(days=days_ago):%Y%m%d}.eml"
    return fname, content


def _gen_standard_memo() -> tuple[str, str]:
    """Returns (filename, content) for a plausible internal memo."""
    author = _name()
    to_name = _name()
    days_ago = random.randint(1, 90)
    topics = [
        ("Q4 Budget Allocation Review", "budget_q4"),
        ("Gas Scheduling — December Nominations", "gas_schedule_dec"),
        ("Risk Limits Update", "risk_limits_update"),
        ("Counterparty Credit Review", "credit_review"),
        ("Market Position Summary — Week 47", "position_summary_w47"),
    ]
    title, slug = random.choice(topics)
    content = (
        f"MEMORANDUM\n{'─'*60}\n"
        f"TO:      {to_name}, {_dept()}\n"
        f"FROM:    {author}, {_dept()}\n"
        f"DATE:    {(datetime(2001,11,30)-timedelta(days=days_ago)).strftime('%B %d, %Y')}\n"
        f"SUBJECT: {title}\n{'─'*60}\n\n"
        f"This memo summarises the current position and outlines recommended actions "
        f"for the {_dept()} team ahead of the next reporting cycle.\n\n"
        f"Please review and advise on any adjustments prior to the committee meeting.\n\n"
        f"Regards,\n{author}\n"
    )
    fname = f"{slug}_{(datetime(2001,11,30)-timedelta(days=days_ago)):%Y%m%d}.txt"
    return fname, content


def _ticker() -> str:
    return random.choice(_TICKERS)


# ── High-value asset templates (Rule 4.2 — High-Alert) ─────────────────────

def _gen_confidential_memo() -> tuple[str, str]:
    """Returns (filename, content) for a CONFIDENTIAL-stamped high-value memo."""
    author   = _name()
    to_name  = _name()
    days_ago = random.randint(1, 30)
    amount   = random.randint(50, 950) * 1_000_000
    deal_topics = [
        ("Project Condor — Acquisition Term Sheet",   "project_condor_termsheet"),
        ("Meridian Gas Assets — Divestiture Analysis","meridian_divestiture"),
        ("Project Atlas — Board Approval Memo",        "project_atlas_board"),
        ("Clearwater JV — NDA and Exclusivity",        "clearwater_jv_nda"),
        ("Northern Pipeline — Restructuring Options",  "northern_pipeline_restr"),
        ("Offshore Portfolio — Risk Disclosure",       "offshore_risk_disclosure"),
    ]
    title, slug = random.choice(deal_topics)
    content = (
        f"{'*'*62}\n"
        f"*  CONFIDENTIAL — ATTORNEY-CLIENT PRIVILEGE              *\n"
        f"*  NOT FOR DISTRIBUTION — ENRON CORP. INTERNAL USE ONLY  *\n"
        f"{'*'*62}\n\n"
        f"MEMORANDUM\n{'─'*60}\n"
        f"TO:      {to_name}, {_dept()}\n"
        f"FROM:    {author}, {_dept()}\n"
        f"DATE:    {(datetime(2001,11,30)-timedelta(days=days_ago)).strftime('%B %d, %Y')}\n"
        f"RE:      {title}\n"
        f"MATTER:  PRIVILEGED & CONFIDENTIAL\n{'─'*60}\n\n"
        f"1. EXECUTIVE SUMMARY\n\n"
        f"   This memorandum sets forth the key terms and conditions "
        f"associated with the above-referenced transaction. Total consideration "
        f"is estimated at ${amount:,.0f}. This document is subject to legal review "
        f"and requires Board sign-off prior to disclosure.\n\n"
        f"2. BACKGROUND\n\n"
        f"   Management has identified this opportunity as consistent with the "
        f"company's strategic objectives. Preliminary due diligence has been "
        f"completed by the {_dept()} team in coordination with outside counsel.\n\n"
        f"3. RECOMMENDED ACTION\n\n"
        f"   Authorise management to proceed to binding term sheet, subject to "
        f"satisfactory completion of financial and legal due diligence.\n\n"
        f"4. NEXT STEPS\n\n"
        f"   Please confirm your approval by COB {(datetime(2001,11,30)-timedelta(days=days_ago-3)).strftime('%B %d')}.\n\n"
        f"{'─'*60}\n"
        f"This document is classified CONFIDENTIAL. Unauthorised disclosure\n"
        f"is prohibited under Enron Corp. Information Security Policy §4.2.\n"
    )
    fname = f"CONFIDENTIAL_{slug}_{(datetime(2001,11,30)-timedelta(days=days_ago)):%Y%m%d}.txt"
    return fname, content


def _gen_confidential_email() -> tuple[str, str]:
    """Returns (filename, content) for a CONFIDENTIAL-flagged deal email."""
    sender    = _name()
    recipient = _name()
    days_ago  = random.randint(1, 21)
    amount    = random.randint(10, 400) * 1_000_000
    deal_names = ["Condor", "Atlas", "Mercury", "Clearwater", "Meridian", "Northgate"]
    deal = random.choice(deal_names)
    content = (
        f"From: {sender} <{_email(sender)}>\n"
        f"To: {recipient} <{_email(recipient)}>\n"
        f"Date: {_date(days_ago)}\n"
        f"Subject: [CONFIDENTIAL] Project {deal} — DO NOT FORWARD\n"
        f"X-Sensitivity: Company-Confidential\n"
        f"X-Mailer: Lotus Notes 5.0\n\n"
        f"PRIVILEGED AND CONFIDENTIAL\n\n"
        f"{recipient.split()[0]},\n\n"
        f"As discussed, attached is the preliminary financial model for Project {deal}. "
        f"The implied valuation range is ${amount:,.0f} — ${amount*1.2:,.0f} based on current "
        f"assumptions. Please do not circulate outside the deal team.\n\n"
        f"We need to align on the financing structure before the Wednesday call with the "
        f"counterparty. {_name()} from {_dept()} will join to walk through the tax considerations.\n\n"
        f"Please treat this as strictly confidential until further notice.\n\n"
        f"Regards,\n{sender}\n{_dept()}\nEnron Corp. — CONFIDENTIAL\n"
    )
    fname = f"CONFIDENTIAL_Project_{deal}_email_{(datetime(2001,11,30)-timedelta(days=days_ago)):%Y%m%d}.eml"
    return fname, content


# ── Enron corpus reader (Phase 5 — live data path) ─────────────────────────

def _sample_from_enron(n: int) -> list[tuple[str, str]]:
    """
    Samples n files from the live Enron corpus at /data/enron/.
    Returns list of (filename, content) tuples.
    Falls through to template generator if corpus unavailable or insufficient.
    """
    results = []
    if not os.path.isdir(ENRON_DIR):
        return results
    all_files = []
    for root, _, files in os.walk(ENRON_DIR):
        for f in files:
            all_files.append(os.path.join(root, f))
    if len(all_files) < n:
        return results
    sampled = random.sample(all_files, n)
    for path in sampled:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
            fname = f"enron_{os.path.basename(path)}"
            results.append((fname, content))
        except Exception:
            continue
    return results


# ── Public API ─────────────────────────────────────────────────────────────

def populate_decoy_vault(
    user_id: str,
    password: str,
    honeyset_salt: bytes,
    high_value: bool = False
) -> list[str]:
    """
    Generates and XOR-encrypts believable decoy files into vault/decoy/<user_id>/.

    Args:
        user_id       : the user's UUID (determines vault subdirectory)
        password      : the honeyword used for XOR key derivation
        honeyset_salt : per-user salt (matches what was stored at registration)
        high_value    : True → Rule 4.2 High-Alert: prioritise CONFIDENTIAL templates

    Returns:
        List of filenames written to the decoy vault.
    """
    # Late import to avoid circular dependency
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from crypto_engine import xor_encrypt

    vault_dir = os.path.join(DECOY_VAULT, user_id)
    os.makedirs(vault_dir, exist_ok=True)

    count     = HIGH_VALUE_COUNT if high_value else STANDARD_COUNT
    generated: list[tuple[str, str]] = []

    if high_value:
        # Rule 4.2 — CONFIDENTIAL templates take priority
        for _ in range(count // 2 + 1):
            generated.append(_gen_confidential_memo())
        for _ in range(count // 2):
            generated.append(_gen_confidential_email())
    else:
        # Try live Enron corpus first
        enron_files = _sample_from_enron(count)
        if enron_files:
            generated = enron_files
        else:
            # Fallback: embedded templates
            for _ in range(count // 2):
                generated.append(_gen_standard_email())
            for _ in range(count - count // 2):
                generated.append(_gen_standard_memo())

    written = []
    for fname, content in generated:
        dest = os.path.join(vault_dir, fname)
        plaintext = content.encode('utf-8')
        encrypted = xor_encrypt(plaintext, password, honeyset_salt)
        with open(dest, 'wb') as f:
            f.write(encrypted)
        written.append(fname)

    return written
