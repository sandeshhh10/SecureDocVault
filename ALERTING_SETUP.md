# Real-Time Intrusion Alerting

SecureDoc detects intrusions with honeywords and deceives them with a decoy
vault. **Alerting closes the loop — the *Respond* pillar:** the moment an
intrusion fires, a live notification is pushed to your phone or a team channel.

Alerts fire on these events:

| Event | When it fires | Level |
|-------|---------------|-------|
| `HONEY_LOGIN_GRANTED` | Someone logs in with a honeyword (routed to the decoy vault) | HIGH if escalated, else NORMAL |
| `ACCOUNT_LOCKED` | An account is locked after repeated failed logins | HIGH |
| `HONEY_ADMIN_LOGIN` | The honey **admin** password is used | HIGH |
| `ADMIN_LOGIN_FAILED` | A wrong admin password is tried | NORMAL |

Alerting is **off until you configure a channel**, and it's completely
optional — with nothing set, the app behaves exactly as before. Sending is
non-blocking and best-effort: a slow or broken alert endpoint never delays or
changes what a user (or an intruder) sees.

---

## Option A — Telegram (recommended, ~2 minutes)

Telegram is the fastest channel to set up and demo.

1. **Create a bot.** In Telegram, message **@BotFather** → send `/newbot` →
   follow the prompts. It gives you a **bot token** like
   `123456789:ABCdef...`.
2. **Get your chat ID.** Send any message to your new bot, then open:
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
   in a browser and copy the `chat.id` value from the JSON
   (e.g. `987654321`).
3. **Add to your `.env`:**
   ```
   ALERT_TELEGRAM_TOKEN=123456789:ABCdef...
   ALERT_TELEGRAM_CHAT_ID=987654321
   ```
4. Restart the app. On the admin dashboard you'll see **Real-Time Alerting ●
   Active — Channels: Telegram**. Click **Send Test Alert** to confirm.

---

## Option B — Webhook (Slack / Discord / custom)

Any endpoint that accepts a JSON `POST` works. The payload looks like:

```json
{
  "text": "🚨 SecureDoc Intrusion Alert\nEvent: HONEY_LOGIN_GRANTED\n...",
  "content": "…same text… (Discord field name)",
  "event": {
    "event_type": "HONEY_LOGIN_GRANTED",
    "username": "kamal",
    "ip": "41.x.x.x",
    "alert_level": "HIGH",
    "detail": "Honeyword slot 0 matched — intruder routed to the decoy vault.",
    "timestamp": "2026-07-23 14:03:11 UTC"
  }
}
```

- **Slack:** create an Incoming Webhook and use its URL (`text` is rendered).
- **Discord:** use a channel webhook and append `` to the URL if you like
  (`content` is rendered).

```
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

You can enable Telegram **and** a webhook at the same time — every configured
channel receives each alert.

---

## Option C — Email (SMTP, e.g. Gmail)

The simplest "it landed in my inbox" demo. Using Gmail:

1. Turn on **2-Step Verification** for your Google account.
2. Create an **App Password**: Google Account → Security → App passwords →
   generate one for "Mail". You get a 16-character password.
3. **Add to your `.env`:**
   ```
   ALERT_SMTP_HOST=smtp.gmail.com
   ALERT_SMTP_PORT=587
   ALERT_SMTP_USER=youraddress@gmail.com
   ALERT_SMTP_PASSWORD=your-16-char-app-password
   ALERT_EMAIL_TO=where-to-send@example.com
   ```
4. Restart, then click **Send Test Alert** on the admin dashboard — an email
   titled `SecureDoc Alert: ALERT_TEST` should arrive.

> Note: this uses a plain STARTTLS SMTP send — fine for a college demo. For a
> real deployment you'd use a transactional email provider and keep the app
> password out of source control (it already lives only in the git-ignored
> `.env`).

Any combination of channels can run at once — each configured channel receives
every alert.

---

## Tuning

| Variable | Default | Purpose |
|----------|---------|---------|
| `ALERT_THROTTLE_SECONDS` | `60` | Suppress duplicate alerts for the same event/user/IP within this window, so a burst of retries doesn't spam you. |

## Demo script (for a presentation)

1. Configure Telegram and open the chat on your phone (mirror it to the screen).
2. On the app, sign in as an intruder — e.g. `kamal` with the decoy password.
3. The intruder lands in the (fake) vault, sees nothing unusual — **and your
   phone buzzes instantly** with the honeyword alert. Detect → Deceive → Respond.
