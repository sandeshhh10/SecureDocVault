"""
log_analytics.py — Admin Dashboard Chart Aggregation
====================================================
Secure-Doc · A.N.T. Architecture

Turns a list of parsed audit-log entries (JSON-Lines dicts, as read by
app._read_log) into ready-to-render chart data for the admin dashboard:

  • timeline  — events per day over a trailing window, pre-projected into SVG
                coordinates so the template only has to draw <polyline>/<path>.
  • types     — event-type breakdown (horizontal magnitude bars).
  • alerts    — NONE / NORMAL / HIGH split (status-coloured segments).

All geometry is computed here (pure Python, no dependencies) so the template
stays declarative and the numbers are testable in isolation. The same function
serves both the real intrusion log and the fake "clean" log — the intruder sees
a plausible, populated dashboard with no observable difference (Rule 1).
"""

from collections import Counter, OrderedDict
from datetime import datetime, timezone, timedelta

# ── SVG canvas for the timeline (matches the CSS in admin_dashboard.html) ────
TL_WIDTH   = 720
TL_HEIGHT  = 190
TL_PAD_L   = 10
TL_PAD_R   = 10
TL_PAD_T   = 16
TL_PAD_B   = 26

TIMELINE_DAYS = 14   # trailing window shown on the trend chart
TOP_TYPES     = 8    # cap on distinct event types in the breakdown


def _event_type(entry: dict) -> str:
    """Best-effort event label — real events use event_type, honey uses action_taken."""
    return entry.get('event_type') or entry.get('action_taken') or 'UNKNOWN'


def _entry_date(entry: dict):
    """Returns the UTC date of an entry, or None if the timestamp is unusable."""
    ts = entry.get('timestamp')
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date()


def _build_timeline(entries: list[dict], today) -> dict:
    """Events-per-day over the trailing window, projected to SVG coordinates."""
    # Seed every day in the window with 0 so gaps render as a true baseline.
    days = OrderedDict()
    start = today - timedelta(days=TIMELINE_DAYS - 1)
    for i in range(TIMELINE_DAYS):
        d = start + timedelta(days=i)
        days[d] = 0

    for e in entries:
        d = _entry_date(e)
        if d is not None and d in days:
            days[d] += 1

    counts = list(days.values())
    max_count = max(counts) if counts else 0
    plot_w = TL_WIDTH - TL_PAD_L - TL_PAD_R
    plot_h = TL_HEIGHT - TL_PAD_T - TL_PAD_B
    baseline_y = TL_HEIGHT - TL_PAD_B

    n = len(counts)
    # Even horizontal spacing; single-point guard avoids a divide-by-zero.
    step = plot_w / (n - 1) if n > 1 else 0

    points = []
    dots = []
    day_list = list(days.keys())
    for i, (d, c) in enumerate(zip(day_list, counts)):
        x = TL_PAD_L + step * i
        y = baseline_y - (c / max_count * plot_h if max_count else 0)
        points.append((round(x, 1), round(y, 1)))
        dots.append({
            'x': round(x, 1),
            'y': round(y, 1),
            'count': c,
            'label': d.strftime('%d %b'),
        })

    polyline = ' '.join(f'{x},{y}' for x, y in points)
    # Closed area path: line across the top, then down to the baseline and back.
    if points:
        area = (f'M {points[0][0]},{baseline_y} '
                + ' '.join(f'L {x},{y}' for x, y in points)
                + f' L {points[-1][0]},{baseline_y} Z')
    else:
        area = ''

    # Sparse x-axis labels — first, middle, last — to avoid crowding.
    axis = []
    if n:
        for idx in sorted({0, n // 2, n - 1}):
            axis.append({'x': round(TL_PAD_L + step * idx, 1),
                         'label': day_list[idx].strftime('%d %b')})

    return {
        'width': TL_WIDTH, 'height': TL_HEIGHT,
        'baseline_y': baseline_y,
        'max': max_count,
        'total': sum(counts),
        'polyline': polyline,
        'area': area,
        'dots': dots,
        'axis': axis,
        'has_data': sum(counts) > 0,
    }


def _build_types(entries: list[dict]) -> dict:
    """Event-type breakdown as magnitude bars (percentage of the largest bar)."""
    counter = Counter(_event_type(e) for e in entries)
    ranked = counter.most_common(TOP_TYPES)
    top = max((c for _, c in ranked), default=0)
    total = sum(counter.values())
    bars = [{
        'label': label,
        'count': count,
        'pct_of_max': round(count / top * 100, 1) if top else 0,
        'pct_of_total': round(count / total * 100) if total else 0,
    } for label, count in ranked]
    return {'bars': bars, 'distinct': len(counter), 'total': total}


def _build_alerts(entries: list[dict]) -> list[dict]:
    """NONE / NORMAL / HIGH split, ready to render as status-coloured segments."""
    counter = Counter((e.get('alert_level') or 'NONE').upper() for e in entries)
    total = sum(counter.values()) or 1
    order = [('HIGH', 'high'), ('NORMAL', 'normal'), ('NONE', 'none')]
    return [{
        'label': label,
        'cls': cls,
        'count': counter.get(label, 0),
        'pct': round(counter.get(label, 0) / total * 100, 1),
    } for label, cls in order]


def build_chart_data(entries: list[dict], today=None) -> dict:
    """
    Aggregates audit-log entries into chart-ready data.

    `today` is injectable for deterministic tests; it defaults to the current
    UTC date.
    """
    if today is None:
        today = datetime.now(timezone.utc).date()
    return {
        'timeline': _build_timeline(entries, today),
        'types':    _build_types(entries),
        'alerts':   _build_alerts(entries),
    }
