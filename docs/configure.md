# Configuration

Anything you can tune after the stack is running. Two configuration surfaces:

1. **`.env`** on the host (`/home/debian/sentinelmail-gateway/deploy/docker/.env`) — bootstrap secrets + ports + TLS mode. Edit then `docker compose restart <service>`.
2. **Web UI** under Settings → System / Org / MSP — runtime values stored in the database. Apply immediately for most keys.

When the two overlap (e.g. TLS), `.env` wins — Caddy reads it on start, the UI tracks it for future automation.

---

## TLS / HTTPS

Three modes:

| Mode | Behavior | Use |
| --- | --- | --- |
| `off` | plain HTTP on the Caddy port | dev hosts, behind external LB |
| `self_signed` | Caddy issues internal cert (browsers warn) | LAN / internal tools |
| `lets_encrypt` | real ACME against Let's Encrypt | public-facing prod |

Set in `.env`:

```
TLS_MODE=lets_encrypt
TLS_HOSTNAME=mx.example.com
TLS_ACME_EMAIL=you@example.com
```

Apply:

```bash
docker compose --env-file .env -f deploy/docker/docker-compose.yml restart caddy
```

ACME requires inbound port 80 reachable from Let's Encrypt's validators. Certs and the ACME account persist under `/data/caddy` in the `caddy_data` named volume, so container rebuilds and restarts do not request fresh certificates.

---

## DNS

Per managed domain:

```
MX 10 mx.example.com.
```

Plus the gateway's own public name:

```
A mx.example.com → <your public IP>
```

For SPF on outbound (when you eventually relay through the gateway), the recipient's MTA checks the connecting IP. Add it to your domain's SPF as `ip4:<your IP>` or `a:mx.example.com`.

For DKIM signing on outbound, generate a keypair (Rspamd has `rspamadm dkim_keygen`) and publish the public key as a TXT record. (Rspamd milter does the signing; setup docs in MVP 3.)

---

## Ports — what binds where

| Service | Host port (default) | Override env | Purpose |
| --- | --- | --- | --- |
| postfix     | 25, 587 | `SMG_SMTP_PORT`, `SMG_SUBMISSION_PORT` | SMTP / submission |
| caddy       | 80, 443 | `SMG_CADDY_HTTP_PORT`, `SMG_CADDY_HTTPS_PORT` | TLS-terminated UI |
| web (nginx) | 8080    | `SMG_HTTP_PORT` | direct UI (bypasses Caddy; convenient for local dev) |
| api         | 8081    | `SMG_API_PORT` | REST API direct |
| rspamd UI   | 11334   | `SMG_RSPAMD_UI_PORT` | rspamd's own web UI |

If a host already uses 80/443 (e.g. nginx for another site), set `SMG_CADDY_HTTP_PORT=8090` + `SMG_CADDY_HTTPS_PORT=8443` and front it externally. That's how docker02 (the dev environment) runs.

---

## SMTP listen address (`SMG_SMTP_LISTEN_IP`)

Default is `0.0.0.0` — binds all interfaces. Override when a host MTA already owns 127.0.0.1:25 (e.g. Debian's `exim4`):

```
SMG_SMTP_LISTEN_IP=10.1.2.3   # the host's specific external IP
```

That binds postfix to one IP, leaving exim4's localhost-only listener alone. Apply with `docker compose up -d --force-recreate postfix`.

---

## `POSTFIX_MYNETWORKS` — who can use you as a relay

Default `127.0.0.0/8 10.0.0.0/8 172.16.0.0/12` (localhost + RFC1918). **Do not add public IPs unless you intend that specific host to relay outbound through the gateway.** Adding the wrong CIDR turns the gateway into an open relay.

You only need to extend it if:

- Your backend MX needs to send outbound through this gateway → add that backend's `/32`
- Internal application servers send notifications through it → add those `/32`s
- Office NAT sends mail through it → add the NAT's `/32`

---

## Anthropic / Claude AI scoring

The AI scan handler uses Claude when `ANTHROPIC_API_KEY` is set and falls back to a keyword heuristic otherwise. Both modes produce a verdict; Claude is more accurate.

```
ANTHROPIC_API_KEY=sk-ant-api03-...
SMG_AI_MODEL=claude-haiku-4-5-20251001   # optional, sensible default
```

Apply: `docker compose restart worker`.

Body is truncated to 8 KB before sending to Claude — keeps cost predictable and your sender's full body out of the prompt budget.

---

## Threat feeds

System Settings → Threat feeds shows the five registered feeds with per-feed:
- **Enabled** toggle
- **Refresh interval** (30s – 24h)
- **API key** (currently only OpenPhish needs one)
- **Last refresh status** (ok / err / never)

Toggles take effect within one refresh tick — no restart needed.

**Contract:** a feed outage is always a "miss," never an error. Mail flow never blocks on feed availability.

---

## System settings (super_admin)

Under `/system-settings` — applies to the whole gateway:

| Key | Type | Default | What |
| --- | --- | --- | --- |
| `ui.brand_name` | string | `SentinelMail Gateway` | UI header text |
| `mail.hostname` | string | `mx.example.com` | Postfix `myhostname` (restart postfix to apply) |
| `mail.mynetworks` | string | `127.0.0.0/8 10.0.0.0/8 172.16.0.0/12` | trusted relay sources |
| `mail.outbound_relay_host` | string | (empty) | smarthost if you can't deliver directly (ISP blocks port 25) |
| `mail.outbound_relay_port` | int | 25 | smarthost port |
| `message.retention_days` | int | 90 | days before inbox copies and quarantined messages are purged; maximum 365 |
| `quarantine.default_action` | enum | `tag` | what to do over threshold |
| `tls.mode` | enum | `off` | `off` \| `self_signed` \| `lets_encrypt` |
| `tls.hostname` | string | (empty) | FQDN for the cert |
| `tls.acme_email` | string | (empty) | Let's Encrypt contact |

---

## Org settings (org_admin)

Under `/org-settings` — applies to a single organization. Each key with the same name as a system key takes precedence within that org:

| Key | Type | What |
| --- | --- | --- |
| `brand.name` | string | per-org brand name for outbound mail |
| `brand.support_email` | string | shown on quarantine release confirmations |
| `alerts.admin_email` | string | where this org gets notifications |
| `message.retention_days` | int | override the system default for inbox and quarantine retention |
| `digest.frequency` | enum | `off` \| `daily` \| `weekly` end-user digest |

---

## MSP settings (msp_admin)

Under `/msp-settings` — shows your child organizations + a `+ New customer org` button. Each child org's `org_admin` manages their own org without seeing siblings.

The MSP retains visibility across the whole subtree through Domains / Gateways / Quarantine / Users — the tenant scope walks the org parent chain.

---

## User settings (everyone, including admins)

Under `/settings`:

- **Appearance**: theme (6 options) + reduced-motion
- **Account**: change your **email address**, change password, enable/disable TOTP MFA

Email changes take effect on next sign-in. The email card is read-only for `org_user` — they need to ask an admin (admin-tier roles can rename anyone in their scope from **Sidebar → Users**).

These are personal — every signed-in user has them, including super_admin.

---

## See also

- [install.md](install.md) for the first-run setup
- [troubleshoot.md](troubleshoot.md) for what to do when a key change doesn't apply
