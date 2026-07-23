"""
alerting.py — Real-Time Intrusion Alerting (the "Respond" pillar)
=================================================================
Secure-Doc · A.N.T. Architecture

Detect (honeywords) and Deceive (decoy vault) already exist. This module closes
the loop with Respond: the moment an intrusion event fires, it pushes a live
alert to whichever channel the operator configured.

Channels (all optional — configured purely from environment variables; if none
are set, the whole module is a silent no-op so tests and offline runs are
unaffected):

  • Telegram   ALERT_TELEGRAM_TOKEN  + ALERT_TELEGRAM_CHAT_ID
  • Webhook    ALERT_WEBHOOK_URL     (generic JSON POST — Slack/Discord/custom)
  • Email      ALERT_SMTP_HOST + ALERT_EMAIL_TO (+ SMTP user/password for Gmail)

Design guarantees:
  • Non-blocking — dispatch runs in a daemon thread with a short socket timeout,
    so a slow or dead alert endpoint never delays the login response.
  • Never raises into the request path — a failed alert must not change what an
    intruder sees (Rule 1 — Honey Mode Silence). All errors are swallowed and
    printed to the server console only.
  • Best-effort de-duplication — the same (event, user, ip) is not re-sent within
    ALERT_THROTTLE_SECONDS, so a burst of retries doesn't spam the channel.
  • Stdlib only — uses urllib, no extra dependency.

Configuration is read from the environment at send time. The project's .env is
already loaded into os.environ by db_backend on import, so a .env entry works
the same as a real environment variable.
"""

import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

# ── Tunables ────────────────────────────────────────────────────────────────
HTTP_TIMEOUT      = 5      # seconds — cap on each outbound alert request
THROTTLE_SECONDS  = int(os.environ.get('ALERT_THROTTLE_SECONDS', '60') or '60')

# In-memory de-dup cache: {dedup_key: last_sent_epoch}. Process-local, which is
# fine — its only job is to suppress rapid duplicates from one running server.
_last_sent: dict[str, float] = {}
_lock = threading.Lock()


# ── Configuration helpers ───────────────────────────────────────────────────
def _telegram_conf() -> tuple[str, str] | None:
    token = os.environ.get('ALERT_TELEGRAM_TOKEN', '').strip()
    chat  = os.environ.get('ALERT_TELEGRAM_CHAT_ID', '').strip()
    return (token, chat) if token and chat else None


def _webhook_url() -> str:
    return os.environ.get('ALERT_WEBHOOK_URL', '').strip()


def _email_conf() -> dict | None:
    host = os.environ.get('ALERT_SMTP_HOST', '').strip()
    to   = os.environ.get('ALERT_EMAIL_TO', '').strip()
    if not (host and to):
        return None
    user = os.environ.get('ALERT_SMTP_USER', '').strip()
    return {
        'host':     host,
        'port':     int(os.environ.get('ALERT_SMTP_PORT', '587') or '587'),
        'user':     user,
        'password': os.environ.get('ALERT_SMTP_PASSWORD', '').strip(),
        'to':       to,
        'from':     os.environ.get('ALERT_EMAIL_FROM', '').strip() or user or to,
    }


def active_channels() -> list[str]:
    """Names of the currently configured channels (for the admin status panel)."""
    channels = []
    if _telegram_conf():
        channels.append('Telegram')
    if _webhook_url():
        channels.append('Webhook')
    if _email_conf():
        channels.append('Email')
    return channels


def enabled() -> bool:
    """True if at least one alert channel is configured."""
    return bool(active_channels())


# ── Message formatting ──────────────────────────────────────────────────────
_EMOJI = {
    'HIGH':   '🚨',
    'NORMAL': '⚠️',
    'TEST':   '✅',
}


def _format_text(event: dict) -> str:
    level = (event.get('alert_level') or 'NORMAL').upper()
    icon  = _EMOJI.get(level, '⚠️')
    lines = [f"{icon} SecureDoc Intrusion Alert",
             f"Event: {event.get('event_type', 'UNKNOWN')}",
             f"Level: {level}"]
    if event.get('username'):
        lines.append(f"User:  {event['username']}")
    if event.get('ip'):
        lines.append(f"IP:    {event['ip']}")
    lines.append(f"Time:  {event.get('timestamp')}")
    if event.get('detail'):
        lines.append(f"Detail: {event['detail']}")
    return '\n'.join(lines)


# ── Channel senders (best-effort, each isolated) ────────────────────────────
def _post(url: str, data: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    urllib.request.urlopen(req, timeout=HTTP_TIMEOUT).read()


def _send_telegram(text: str) -> None:
    conf = _telegram_conf()
    if not conf:
        return
    token, chat_id = conf
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({'chat_id': chat_id, 'text': text}).encode('utf-8')
    _post(url, body, {'Content-Type': 'application/json'})


def _send_webhook(event: dict, text: str) -> None:
    url = _webhook_url()
    if not url:
        return
    # `text` and `content` cover Slack and Discord's default field names; the
    # full structured event is included for custom consumers.
    body = json.dumps({'text': text, 'content': text, 'event': event}).encode('utf-8')
    _post(url, body, {'Content-Type': 'application/json'})


def _send_email(event: dict, text: str) -> None:
    conf = _email_conf()
    if not conf:
        return
    import smtplib
    import socket
    import ssl
    from email.message import EmailMessage

    msg = EmailMessage()
    msg['Subject'] = f"SecureDoc Alert: {event.get('event_type', 'INTRUSION')}"
    msg['From']    = conf['from']
    msg['To']      = conf['to']
    msg.set_content(text)

    # Force IPv4. Some hosts (notably Render's free tier) have NO IPv6 egress, so
    # connecting to Gmail's IPv6 SMTP address fails with 'Network is unreachable'.
    # Resolve the host to an IPv4 address and connect to that; fall back to the
    # hostname if resolution fails (e.g. IPv4 not available).
    host = conf['host']
    try:
        host = socket.getaddrinfo(conf['host'], conf['port'],
                                  socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        pass

    # We connected by IP, so the TLS cert hostname won't match — relax
    # verification. This is a demo alerting channel, not a data path.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with smtplib.SMTP(host, conf['port'], timeout=HTTP_TIMEOUT) as smtp:
        smtp.ehlo()
        try:
            smtp.starttls(context=ctx)
            smtp.ehlo()
        except smtplib.SMTPException:
            pass   # some local/test relays don't offer TLS — send anyway
        if conf['user'] and conf['password']:
            smtp.login(conf['user'], conf['password'])
        smtp.send_message(msg)


def _dispatch(event: dict) -> None:
    text = _format_text(event)
    for sender in (lambda: _send_telegram(text),
                   lambda: _send_webhook(event, text),
                   lambda: _send_email(event, text)):
        try:
            sender()
        except Exception as exc:                     # never propagate
            print(f"[alerting] channel send failed: {exc}")


# ── Public API ──────────────────────────────────────────────────────────────
def send_alert(event_type: str, *, username: str | None = None,
               ip: str | None = None, alert_level: str = 'NORMAL',
               detail: str | None = None) -> bool:
    """
    Fire a security alert. Returns True if it was dispatched, False if it was
    suppressed (no channel configured, or throttled as a duplicate).

    Dispatch happens on a daemon thread, so this returns immediately and never
    blocks or breaks the caller's request path.
    """
    if not enabled():
        return False

    now = time.time()
    dedup_key = f"{event_type}|{username or ''}|{ip or ''}"
    with _lock:
        last = _last_sent.get(dedup_key, 0.0)
        if now - last < THROTTLE_SECONDS:
            return False
        _last_sent[dedup_key] = now

    event = {
        'event_type':  event_type,
        'username':    username,
        'ip':          ip,
        'alert_level': alert_level,
        'detail':      detail,
        'timestamp':   datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
    }
    threading.Thread(target=_dispatch, args=(event,), daemon=True).start()
    return True


def send_test_alert(triggered_by: str = 'admin') -> bool:
    """Send a test alert (used by the admin 'Send test alert' button)."""
    if not enabled():
        return False
    event = {
        'event_type':  'ALERT_TEST',
        'username':    triggered_by,
        'ip':          None,
        'alert_level': 'TEST',
        'detail':      'This is a test alert from the SecureDoc admin panel.',
        'timestamp':   datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
    }
    threading.Thread(target=_dispatch, args=(event,), daemon=True).start()
    return True
