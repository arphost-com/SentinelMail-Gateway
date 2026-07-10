# Backend mail server setup

SentinelMail Gateway sits in front of a real mail server (the "backend MX") that hosts mailboxes. After SentinelMail scans an inbound message, it forwards the clean ones to that backend over SMTP on port 25.

Pick your backend:

- [Mailcow](mailcow.md) — Dockerized all-in-one (Postfix + Dovecot + SOGo + Rspamd)
- [Plain Postfix](postfix.md) — vanilla postfix + dovecot install
- [Microsoft Exchange (on-prem)](exchange.md) — Exchange 2016/2019/SE
- [Microsoft 365 / Exchange Online](m365.md) — cloud-hosted Exchange
- [Google Workspace](google-workspace.md) — formerly G Suite
- [Generic SMTP](generic-smtp.md) — any other MTA (cPanel, Plesk, Zimbra, etc.)

All six share the same four-step shape:

1. **Trust SentinelMail's IP** on the backend so it doesn't reject the forwarded mail as "relay access denied".
2. **Register the domain** in the backend so it knows it should host mail for `you@example.com`.
3. **Configure DNS** on the domain (SPF + PTR) so external receivers don't flag SentinelMail's outbound traffic as spoofed.
4. **(Optional) honor SentinelMail's scoring headers** so flagged mail lands in Junk instead of Inbox.

The per-backend pages give you the exact knobs for that platform.

---

## Direction of mail flow

```
internet → spam01:25 (SentinelMail)  →  backend MX:25 (Mailcow / Exchange / etc.) → mailbox
                       ↑
                       │
              SentinelMail's Gateway record
              (Sidebar → Gateways) points here
```

SentinelMail is your **public MX**. The backend is internal-only — its DNS doesn't need to be reachable from the open internet. If you must keep it reachable for ActiveSync / IMAP / OWA / etc., put it on a different hostname (e.g. `mailbox.example.com`) and keep `mx.example.com` pointed at SentinelMail.

---

## Common gotchas, applies to all backends

- **SPF for the gateway hostname** — receivers of bounces care. Add `v=spf1 ip4:<spam01-ip> -all` to the txt of the `POSTFIX_MYHOSTNAME` domain.
- **PTR / reverse DNS** for the gateway IP — set at your VPS provider, not in your zone. Without it, Gmail and Outlook will tag SentinelMail's outbound traffic as spam.
- **Don't double-score.** If the backend has its own rspamd / SpamAssassin, either disable it or set it to header-only and trust SentinelMail's scoring. Otherwise every message is scanned twice and the verdicts can disagree.
- **Listen ports on the backend.** SentinelMail forwards on plain port 25. If your backend only listens on 587 (submission) or 465 (smtps), you need to either expose 25 inside the network or change the Gateway's port in the SentinelMail UI.
