"""
enron_loader.py — Phase 5: Live Enron Corpus Loader & Document Renderer
========================================================================
Secure-Doc · A.N.T. Architecture

Reads refined_enron.json, parses each record's structured metadata fields,
and renders them into believable decoy documents:

  .txt  — plain-text archive analysis report (always available)
  .pdf  — formatted PDF report via reportlab (if available; graceful fallback)

Each call to generate_decoy_document() picks one record at random, wraps it
in a realistic internal report format, and returns (filename, bytes).

The caller (honeyfile_gen.py / vault_watchdog.py) handles XOR encryption
and writing to vault/decoy/<user_id>/. This module is format-only.
"""

import json
import os
import re
import random
import textwrap
from datetime import datetime
from typing import Literal

# ── Paths ──────────────────────────────────────────────────────────────────
_BASE   = os.path.join(os.path.dirname(__file__), '..')
JSON_PATH = os.path.abspath(os.path.join(_BASE, 'data', 'enron', 'refined_enron.json'))

# ── Report personas ────────────────────────────────────────────────────────
_ANALYSTS  = ["T. Morrison", "D. Chen", "R. Patel", "K. Okafor",
              "L. Santos", "M. Eriksson", "A. Novak", "S. Huang"]
_DIVISIONS = ["Information Security", "IT Compliance", "Data Governance",
              "Email Infrastructure", "Network Operations", "Risk & Audit"]
_REF_CODES = ["ISR", "ITC", "DGR", "EIA", "NOR", "RAU"]


# ── Record parser ──────────────────────────────────────────────────────────
def _parse_record(raw: str) -> dict:
    """
    Extracts structured fields from a raw refined_enron.json string.

    Example input:
      "Spam ---- - Owner: GP - Total number: 1500 emails - Date of first email:
       2003-12-18 - Date of last email: 2005-09-06 - Similars deletion: No -
       Encoding: No Spam:Legitimate rate = 1:3 Total number of emails
       (legitimate + spam): 5975"

    Returns dict with keys: owner, spam_count, first_date, last_date,
    similars_deletion, encoding, spam_ratio, total_count, spam_class
    """
    def _get(pattern, default='Unknown'):
        m = re.search(pattern, raw)
        return m.group(1).strip() if m else default

    # Determine if high-spam or balanced
    ratio_raw = _get(r'rate\s*=\s*([0-9:]+)', '1:3')
    parts     = ratio_raw.split(':')
    is_high_spam = int(parts[0]) > int(parts[1]) if len(parts) == 2 else False

    return {
        'owner':            _get(r'Owner:\s*([^-]+)'),
        'spam_count':       _get(r'Total number:\s*(\d+)'),
        'first_date':       _get(r'Date of first email:\s*(\d{4}-\d{2}-\d{2})'),
        'last_date':        _get(r'Date of last email:\s*(\d{4}-\d{2}-\d{2})'),
        'similars_deletion':_get(r'Similars deletion:\s*(\w+)'),
        'encoding':         _get(r'Encoding:\s*(\w+)'),
        'spam_ratio':       ratio_raw,
        'total_count':      _get(r'Total number of emails \([^)]+\):\s*(\d+)'),
        'is_high_spam':     is_high_spam,
        'raw':              raw.strip(),
    }


def _load_records() -> list[dict]:
    """Loads and parses all records from refined_enron.json."""
    with open(JSON_PATH, 'r', encoding='utf-8') as f:
        raw_list = json.load(f)
    return [_parse_record(r) for r in raw_list]


# ── TXT renderer ──────────────────────────────────────────────────────────
def _render_txt(rec: dict, analyst: str, division: str, ref: str,
                generated: str) -> bytes:
    """
    Renders a record as a plain-text internal archive analysis report.
    Format mimics a real IT/compliance document.
    """
    spam_int  = int(rec['spam_count']) if rec['spam_count'].isdigit() else 0
    total_int = int(rec['total_count']) if rec['total_count'].isdigit() else 0
    legit_int = total_int - spam_int if total_int > spam_int else 0
    pct_spam  = f"{(spam_int / total_int * 100):.1f}%" if total_int else "N/A"

    lines = [
        "=" * 68,
        "  INTERNAL REPORT — EMAIL ARCHIVE ANALYSIS",
        "  ENRON CORPORATION — INFORMATION SERVICES DIVISION",
        "=" * 68,
        "",
        f"  Reference    : {ref}-{generated[:4]}-{random.randint(1000,9999):04d}",
        f"  Prepared by  : {analyst}, {division}",
        f"  Generated    : {generated}",
        f"  Classification: INTERNAL USE ONLY",
        "",
        "-" * 68,
        "  1. DATASET OVERVIEW",
        "-" * 68,
        "",
        f"  Archive Owner      : {rec['owner']}",
        f"  Corpus Date Range  : {rec['first_date']}  →  {rec['last_date']}",
        f"  Total Messages     : {int(rec['total_count']):,}" if rec['total_count'].isdigit() else f"  Total Messages     : {rec['total_count']}",
        f"  Spam Messages      : {spam_int:,}",
        f"  Legitimate Messages: {legit_int:,}",
        f"  Spam/Legitimate    : {rec['spam_ratio']}",
        f"  Spam Proportion    : {pct_spam}",
        "",
        "-" * 68,
        "  2. PROCESSING PARAMETERS",
        "-" * 68,
        "",
        f"  Duplicate Removal  : {rec['similars_deletion']}",
        f"  Encoding Applied   : {rec['encoding']}",
        f"  Filter Method      : {'SpamAssassin + HoneyPot trap' if 'HoneyPot' in rec['owner'] else 'Manual review + automated tagging'}",
        "",
        "-" * 68,
        "  3. ANALYSIS NOTES",
        "-" * 68,
        "",
    ]

    if rec['is_high_spam']:
        notes = (
            f"  The {rec['owner']} corpus exhibits a high spam prevalence ({pct_spam}), "
            f"consistent with aggressive harvesting activity during the collection "
            f"window {rec['first_date']} to {rec['last_date']}. The 3:1 spam-to-legitimate "
            f"ratio exceeds the departmental baseline of 1:3 by a factor of nine. "
            f"Recommend escalation to the {division} team for further review."
        )
    else:
        notes = (
            f"  The {rec['owner']} corpus reflects a balanced spam distribution ({pct_spam}), "
            f"within acceptable thresholds for the period {rec['first_date']} to "
            f"{rec['last_date']}. No anomalous delivery patterns detected. "
            f"Archive is suitable for inclusion in the consolidated compliance dataset."
        )

    for line in textwrap.wrap(notes, width=66, initial_indent='  ', subsequent_indent='  '):
        lines.append(line)

    lines += [
        "",
        "-" * 68,
        "  4. RECOMMENDED ACTION",
        "-" * 68,
        "",
        f"  {'⚑  Flag for Security Review — elevated spam volume detected.' if rec['is_high_spam'] else '✓  Archive cleared for standard retention policy.'}",
        f"  Retain record per Email Retention Schedule §3.4 (7-year hold).",
        "",
        "=" * 68,
        f"  END OF REPORT — {ref} — {generated}",
        "=" * 68,
        "",
    ]
    return '\n'.join(lines).encode('utf-8')


# ── PDF renderer ──────────────────────────────────────────────────────────
def _render_pdf(rec: dict, analyst: str, division: str, ref: str,
                generated: str) -> bytes | None:
    """
    Renders a record as a formatted PDF using reportlab.
    Returns None if reportlab is unavailable (caller falls back to .txt).
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units     import cm
        from reportlab.lib           import colors
        from reportlab.platypus      import (SimpleDocTemplate, Paragraph,
                                             Spacer, Table, TableStyle, HRFlowable)
        from io import BytesIO
    except ImportError:
        return None

    buf    = BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=2.5*cm, rightMargin=2.5*cm,
                               topMargin=2.5*cm, bottomMargin=2.5*cm)
    styles = getSampleStyleSheet()

    DARK   = colors.HexColor('#1a1a2e')
    ACCENT = colors.HexColor('#1d4ed8')
    GREY   = colors.HexColor('#64748b')
    LIGHT  = colors.HexColor('#f1f5f9')

    title_style = ParagraphStyle('Title', parent=styles['Title'],
        fontSize=16, textColor=DARK, spaceAfter=4, leading=20)
    sub_style   = ParagraphStyle('Sub', parent=styles['Normal'],
        fontSize=9, textColor=GREY, spaceAfter=2)
    head_style  = ParagraphStyle('Head', parent=styles['Heading2'],
        fontSize=11, textColor=ACCENT, spaceBefore=14, spaceAfter=6)
    body_style  = ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=9, textColor=DARK, leading=14, spaceAfter=6)
    mono_style  = ParagraphStyle('Mono', parent=styles['Code'],
        fontSize=8, textColor=colors.HexColor('#334155'),
        backColor=LIGHT, borderPadding=6)

    spam_int  = int(rec['spam_count'])  if rec['spam_count'].isdigit()  else 0
    total_int = int(rec['total_count']) if rec['total_count'].isdigit() else 0
    legit_int = total_int - spam_int if total_int > spam_int else 0
    pct_spam  = f"{(spam_int / total_int * 100):.1f}%" if total_int else 'N/A'

    ref_no = f"{ref}-{generated[:4]}-{random.randint(1000,9999):04d}"

    story = [
        Paragraph("ENRON CORPORATION", sub_style),
        Paragraph("Email Archive Analysis Report", title_style),
        HRFlowable(width='100%', thickness=1, color=ACCENT),
        Spacer(1, 8),

        # Meta table
        Table([
            ['Reference', ref_no,      'Prepared by', analyst],
            ['Date',      generated,   'Division',    division],
            ['Class',     'INTERNAL USE ONLY', 'Status',
             '⚑ Flagged' if rec['is_high_spam'] else '✓ Cleared'],
        ], colWidths=[3*cm, 5.5*cm, 3*cm, 5*cm],
           style=TableStyle([
               ('FONTSIZE',     (0,0), (-1,-1), 8),
               ('FONTNAME',     (0,0), (0,-1), 'Helvetica-Bold'),
               ('FONTNAME',     (2,0), (2,-1), 'Helvetica-Bold'),
               ('TEXTCOLOR',    (0,0), (0,-1), GREY),
               ('TEXTCOLOR',    (2,0), (2,-1), GREY),
               ('ROWBACKGROUNDS',(0,0),(-1,-1), [LIGHT, colors.white]),
               ('GRID',         (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
               ('TOPPADDING',   (0,0), (-1,-1), 5),
               ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ])),
        Spacer(1, 14),

        Paragraph("1. Dataset Overview", head_style),
        Table([
            ['Archive Owner',       rec['owner']],
            ['Collection Period',   f"{rec['first_date']}  →  {rec['last_date']}"],
            ['Total Messages',      f"{total_int:,}" if total_int else rec['total_count']],
            ['Spam Messages',       f"{spam_int:,}"],
            ['Legitimate Messages', f"{legit_int:,}"],
            ['Spam / Legitimate',   rec['spam_ratio']],
            ['Spam Proportion',     pct_spam],
        ], colWidths=[5*cm, 11.5*cm],
           style=TableStyle([
               ('FONTSIZE',      (0,0), (-1,-1), 9),
               ('FONTNAME',      (0,0), (0,-1), 'Helvetica-Bold'),
               ('TEXTCOLOR',     (0,0), (0,-1), GREY),
               ('ROWBACKGROUNDS',(0,0),(-1,-1), [LIGHT, colors.white]),
               ('GRID',          (0,0),(-1,-1), 0.3, colors.HexColor('#e2e8f0')),
               ('TOPPADDING',    (0,0),(-1,-1), 5),
               ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ])),
        Spacer(1, 6),

        Paragraph("2. Processing Parameters", head_style),
        Table([
            ['Duplicate Removal', rec['similars_deletion']],
            ['Encoding Applied',  rec['encoding']],
            ['Filter Method',     'SpamAssassin + HoneyPot trap'
                                  if 'HoneyPot' in rec['owner']
                                  else 'Manual review + automated tagging'],
        ], colWidths=[5*cm, 11.5*cm],
           style=TableStyle([
               ('FONTSIZE',      (0,0),(-1,-1), 9),
               ('FONTNAME',      (0,0),(0,-1),  'Helvetica-Bold'),
               ('TEXTCOLOR',     (0,0),(0,-1),  GREY),
               ('ROWBACKGROUNDS',(0,0),(-1,-1), [LIGHT, colors.white]),
               ('GRID',          (0,0),(-1,-1), 0.3, colors.HexColor('#e2e8f0')),
               ('TOPPADDING',    (0,0),(-1,-1), 5),
               ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ])),
        Spacer(1, 6),

        Paragraph("3. Analysis Notes", head_style),
        Paragraph(
            f"The <b>{rec['owner']}</b> corpus {'exhibits a high spam prevalence' if rec['is_high_spam'] else 'reflects a balanced spam distribution'} "
            f"({pct_spam}), collected between {rec['first_date']} and {rec['last_date']}. "
            + ('The 3:1 spam-to-legitimate ratio exceeds the departmental baseline by a factor of nine. '
               f'Recommend escalation to {division} for further review.'
               if rec['is_high_spam'] else
               'No anomalous delivery patterns detected. Archive is suitable for inclusion in the consolidated compliance dataset.'),
            body_style
        ),
        Spacer(1, 6),

        Paragraph("4. Recommended Action", head_style),
        Paragraph(
            '<font color="#ef4444"><b>⚑ Flag for Security Review</b></font> — elevated spam volume detected.'
            if rec['is_high_spam'] else
            '<font color="#16a34a"><b>✓ Archive Cleared</b></font> — standard retention policy applies.',
            body_style
        ),
        Paragraph(
            "Retain record per Email Retention Schedule §3.4 (7-year hold).", body_style
        ),
        Spacer(1, 14),
        HRFlowable(width='100%', thickness=0.5, color=GREY),
        Paragraph(
            f"<font size='7' color='#94a3b8'>Enron Corporation — Internal Use Only — "
            f"Ref: {ref_no} — Generated: {generated}</font>",
            ParagraphStyle('footer', parent=styles['Normal'],
                           alignment=1, spaceAfter=0)
        ),
    ]

    doc.build(story)
    return buf.getvalue()


# ── Public API ─────────────────────────────────────────────────────────────
def generate_decoy_document(fmt: Literal['txt', 'pdf', 'random'] = 'random') \
        -> tuple[str, bytes]:
    """
    Picks one record at random from refined_enron.json and renders it
    as an internal archive analysis report.

    Args:
        fmt : 'txt' | 'pdf' | 'random' (default: randomly choose txt or pdf)

    Returns:
        (filename, file_bytes) — ready for XOR encryption and vault write.
    """
    records  = _load_records()
    rec      = random.choice(records)
    analyst  = random.choice(_ANALYSTS)
    div_idx  = random.randrange(len(_DIVISIONS))
    division = _DIVISIONS[div_idx]
    ref      = _REF_CODES[div_idx]
    generated = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # Determine format
    if fmt == 'random':
        fmt = random.choice(['txt', 'pdf'])

    slug  = re.sub(r'[^a-z0-9]+', '_', rec['owner'].lower())[:20]
    stamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

    if fmt == 'pdf':
        data = _render_pdf(rec, analyst, division, ref, generated)
        if data:
            return f"ArchiveReport_{slug}_{stamp}.pdf", data
        # Fallback to txt if reportlab fails
        fmt = 'txt'

    data  = _render_txt(rec, analyst, division, ref, generated)
    return f"ArchiveReport_{slug}_{stamp}.txt", data
