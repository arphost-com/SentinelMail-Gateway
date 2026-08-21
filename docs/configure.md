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

SentinelMail-generated abuse reports and notifications use the system-wide
`mail.system_from_address`. In a hosted deployment, set this to an address in
the provider's own authenticated domain, such as
`abuse-reports@sentinelmail.provider.example`. Customer support addresses are
used as reply/contact addresses and do not need to authorize the SentinelMail
gateway in their SPF records. Self-hosters must ensure the automated sender
domain authorizes the actual outbound relay with aligned SPF or DKIM.

Do not publish a second SPF TXT record. If the sender domain already has SPF,
merge any required `ip4:`, `a:`, or `include:` mechanism into that one record.

`SMG_SYSTEM_FROM_ADDRESS` in `deploy/docker/.env` is the deployment-owned
equivalent of the UI setting and takes precedence on API startup. ARPHost-hosted
SentinelMail uses `abuse-reports@arphost.com`; customer domains do not need an
SPF change for those reports.

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

## AI scoring provider

AI analysis stays in the asynchronous light worker. A super administrator
configures every runtime option under **Configuration → System settings → AI
analysis**:

- AI mode: `disabled`, `suspicious`, or `all`
- provider: `anthropic` or `openai`
- model: optional; blank uses Claude Haiku 4.5 or GPT-5 mini
- Anthropic API key
- OpenAI API key

Keys are encrypted before storage in PostgreSQL, are masked on every settings
read, and are never returned to the browser. `disabled` is the zero-cost default
and queues no AI jobs. `suspicious` analyzes only mail already tagged or held by
deterministic policy. Saving takes effect on the next eligible AI scan without
restarting containers. Missing keys and provider errors remain
explicitly unavailable or inconclusive; heuristics are supporting metadata only.

Borderline mail can optionally be withheld before delivery while asynchronous
analysis runs. This uses the existing quarantine-and-release path; AI and browser
calls never move into the SMTP process. Clean mail is released once all required
jobs finish. Suspicious, failed, inconclusive, or timed-out analysis remains held
for manual review and never generates both an original delivery and a quarantine
notice.

`SMG_SETTINGS_ENCRYPTION_KEY` is the sole deployment-time requirement for this
feature. Bootstrap/deploy generates it once in `deploy/docker/.env`; preserve it
with backups. Losing or rotating it without re-entering the provider keys makes
existing encrypted keys unreadable.

Body text is truncated to 8 KB before either provider request. OpenAI requests
use Structured Outputs and set `store=false`.

---

## Threat feeds

System Settings → Threat feeds shows only providers with a working runtime implementation:
- **Enabled** toggle
- **Refresh interval** (30s – 24h)
- **API key** when the provider requires one
- **Last refresh status** (ok / err / never)

Toggles take effect within one refresh tick — no restart needed.

**Contract:** the SMTP decision path reads only local Redis-cached feed results.
Provider and DNS queries warm that cache asynchronously for repeated campaign
traffic. A feed outage is always a miss, never an SMTP error.

---

## System settings (super_admin)

Under `/system-settings` — applies to the whole gateway:

| Key | Type | Default | What |
| --- | --- | --- | --- |
| `ui.brand_name` | string | `SentinelMail Gateway` | UI header text |
| `mail.hostname` | string | `mx.example.com` | Postfix `myhostname` (restart postfix to apply) |
| `mail.mynetworks` | string | `127.0.0.0/8 10.0.0.0/8 172.16.0.0/12` | trusted relay sources |
| `mail.system_from_address` | string | (empty) | authenticated From address for abuse reports and system email |
| `mail.outbound_relay_host` | string | (empty) | smarthost if you can't deliver directly (ISP blocks port 25) |
| `mail.outbound_relay_port` | int | 25 | smarthost port |
| `message.retention_days` | int | 90 | days before inbox copies and quarantined messages are purged; maximum 365 |
| `quarantine.default_action` | enum | `quarantine` | what to do over threshold |
| `ai.mode` | enum | `disabled` | zero-cost disabled, suspicious-only, or all mail |
| `deep_analysis.enabled` | bool | false | withhold borderline mail until async analysis completes |
| `deep_analysis.min_score` | int | 4 | lowest score eligible for an analysis hold |
| `deep_analysis.timeout_minutes` | int | 15 | timeout before manual review is required |
| `threat_intel.cached_enforcement` | bool | true | enforce local cached reputation hits |
| `tls.mode` | enum | `off` | `off` \| `self_signed` \| `lets_encrypt` |
| `tls.hostname` | string | (empty) | FQDN for the cert |
| `tls.acme_email` | string | (empty) | Let's Encrypt contact |

---

## Org settings (org_admin)

Under `/org-settings` — applies to a single organization. Each key with the same name as a system key takes precedence within that org:

| Key | Type | What |
| --- | --- | --- |
| `brand.name` | string | per-org brand name for outbound mail |
| `brand.support_email` | string | tenant reply/contact address; not the authenticated automated sender |
| `alerts.admin_email` | string | where this org gets notifications |
| `message.retention_days` | int | override the system default for inbox and quarantine retention |
| `digest.frequency` | enum | `off` \| `daily` \| `weekly` end-user digest |

---

## MSP settings (msp_admin)

Under `/msp-settings` — shows your child organizations + a `+ New customer org` button. Each child org's `org_admin` manages their own org without seeing siblings.

The MSP retains visibility across the whole subtree through Domains / Gateways / Quarantine / Users — the tenant scope walks the org parent chain.

---

## Common-scam policy controls

Organization and domain policies can enable or disable the complete common-scam
detector or individual categories. The **Health lead-generation spam** category
uses only fast subject/body checks in the SMTP decision path. It requires a
health or wellness topic, clickbait-style curiosity wording, and multiple
independent claim, authority, sales, or click-through signals before holding a
message. Valid SPF, DKIM, or DMARC authenticates the sender domain but does not
make unsolicited health-offer mail wanted.

The same category intentionally leaves ordinary care-team messages, neutral
research summaries, and educational health newsletters alone. Disable
`common_scam_health_miracle_enabled` only when an organization explicitly wants
to bypass both health-miracle and health lead-generation detection.

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
