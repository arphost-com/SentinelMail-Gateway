# SentinelMail Gateway

Self-hosted, multi-tenant anti-spam / anti-phishing / email-security gateway. Sits in front of one or more mail servers (Mailcow, Postfix, Exchange, Microsoft 365, Google Workspace, generic SMTP) and runs both inline SMTP-side scoring (Postfix + Rspamd + ClamAV) and an async deeper-analysis layer (QR phishing, browser sandbox, AI scoring, outbound compromise).

Designed for both onsite customer installs and direct internet-facing hosted/MSP deployments with delegated administration. WCAG 2.2 AA UI with six themes (Light / Dark / High-Contrast Light / High-Contrast Dark / Colorblind Safe / Large Text) plus reduced-motion.

SentinelMail is sold as infrastructure software, not shared-hosting software. It must run on a VPS, dedicated server, colocated server, or equivalent environment where the operator controls Docker, firewall rules, persistent volumes, SMTP ports, DNS/MX records, TLS, and backups. That requirement is part of the security model: SentinelMail is an internet-facing mail gateway, and shared hosting cannot safely provide the required queue ownership, tenant isolation, certificate persistence, logging, and privileged-port behavior.

- **Task-oriented guides** live in [`docs/`](docs/) — start with [`docs/install.md`](docs/install.md) for a fresh production install
- **Plain-English role guides** live in [`docs/role-guides.md`](docs/role-guides.md) for end users, org admins, MSP admins, and super admins
- **Customer handoff quick start** is available as [`docs/customer-quick-start.md`](docs/customer-quick-start.md) and [`docs/customer-quick-start.pdf`](docs/customer-quick-start.pdf)
- **Bug reports, fixes, and update flow** are covered in [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/contributing.md`](docs/contributing.md)
- **In-app docs** at **Docs** in the sidebar once you're signed in
- **This README** focuses on architecture, REST API, repo layout, and dev quickstart

## Who This Is For

| Deployment | Fit | Notes |
| --- | --- | --- |
| Customer onsite | Yes | Install on the customer's own VPS/server and point their MX records to it. |
| Direct internet-facing SaaS/MSP | Yes | One gateway can host many organizations with delegated admins and tenant-scoped data. |
| Private corporate network | Yes | Use firewall/NAT rules and route scanned mail to the internal downstream mail server. |
| Shared hosting/cPanel-only account | No | Cannot safely bind SMTP ports, run Docker services, persist queues/certs, or control network policy. |

## Plain-English User Docs

Use these when handing the product to non-engineers:

- **End user:** Sign in, turn on 2FA, review quarantined mail, release/delete messages, check own mail logs.
- **Organization admin:** Add domains, configure downstream gateways, manage policies/users, review quarantine/mail logs/threats for their organization.
- **MSP admin:** Create and manage customer organizations, domains, gateways, users, and reports across their customer subtree.
- **Super admin:** Operate the whole gateway, system settings, threat feeds, all tenants, production troubleshooting, and security controls.

The same plain-English guidance is available inside the app under **Docs** so customers do not need shell access or repository access to understand what they can do.

---

## Status

**MVP 1 — shipped**
- Postfix → Rspamd milter (SPF/DKIM/DMARC, greylisting, RBLs, ClamAV)
- Quarantine (list / preview / release / delete)
- Dashboard with 24h disposition stats
- Hierarchical policy engine (per-org + per-domain + hardcoded safe fallback)
- Threat-feed registry with per-feed enable/interval (Spamhaus ZEN/DBL, SpamCop, URLhaus)
- Full UI CRUD for Organizations, Domains, Gateways, Policies, Users
- System Settings + Threat-feeds UI (schema-driven; add a key in Go and it appears in the form)
- Cookie sessions (Argon2id, HttpOnly, Secure, SameSite=Lax) with tier-enforced role assignment
- HMAC-authenticated mail-event ingest endpoint and example Rspamd Lua snippet

**MVP 2 — shipped**
- v1 **QR phishing**: pyzbar decode + URLhaus URL lookup
- v2 **Browser sandbox**: headless Chromium via Playwright in a dedicated worker; screenshot + redirect + password-input + cross-origin-form heuristics
- v3 **AI scoring**: Anthropic Claude (Haiku 4.5 default) with keyword-heuristic fallback when no API key is set
- v4 **Outbound BEC**: recipient fan-out, distinct-domain count, off-hours, BEC-keyword heuristics
- **Auto-trigger** from real mail: the Lua snippet is now baked into the rspamd image and auto-loads; every inbound message fans into the appropriate scan kinds with no operator action

**Nice-to-haves — shipped**
- **Audit log** writer + viewer page (auth events; CRUD events queued)
- **End-user quarantine self-service** (org_user only sees mail addressed to themselves)
- **TOTP MFA** enrollment + login flow (Settings → Account)
- **GitLab CI** via shell runner on docker02 with self-bootstrapping `.env`

**MVP 3 — partially started**
- Reports page with clickable summaries and graph drilldowns is shipped
- SMTP Events page for Postfix-only rejects, TLS failures, and downstream deferrals is shipped
- Not started: link rewriting, SSO, billing hooks, multi-node clustering

---

## Architecture

```
                     Internet
                        │
                        ▼
        ┌───────────────────────────────────┐
        │  Postfix 25/587 (10.10.10.93:25)  │
        └───────────────┬───────────────────┘
                        │ milter
                        ▼
        ┌──────────────────┐   ┌────────────┐
        │  Rspamd          │──►│  ClamAV    │
        │  ├─ SPF/DKIM/DMARC│   └────────────┘
        │  ├─ RBLs (Spamhaus…) │
        │  └─ smg_ingest.lua  ─────────┐
        └──────────────────┘           │
                                       │  HMAC POST
                                       ▼
        ┌──────────────────────────────────┐
        │  Go API  (api:8080)              │
        │  /api/v1/* + /mail/events        │
        │  mail_logs + quarantine_entries  │
        │  spawnScans → Redis              │
        └────┬─────────────────────────────┘
             │
        ┌────▼────────────┐    ┌────────────────────────┐
        │  Redis          │    │  PostgreSQL 16          │
        │  smg:scan_jobs  │    │  organizations, users,   │
        │  …_sandbox      │    │  sessions, domains, …   │
        └────┬────────────┘    └──────────────────────────┘
             │
   ┌─────────┼────────────┐
   ▼         ▼            ▼
 worker  sandbox-worker  (more)
 qr/ai/  Playwright +
 outbound  Chromium

   ▲                ▲
   │ POST result    │ POST result
   └────────────────┴────► /api/v1/scan-callback/{id}/result

        ┌──────────────────────┐
        │  React SPA (nginx)   │
        │  proxies /api → api  │
        └──────────────────────┘
```

**Why two worker images:** the Playwright + Chromium base image is ~1.2 GB. Keeping it isolated in `sandbox-worker` lets `worker` (qr / ai / outbound) stay small (~200 MB) and gives us independent failure domains.

---

## Tech stack

| Layer       | Tech                                                              |
| ---         | ---                                                               |
| Backend     | Go 1.25, chi router, pgx/v5, go-redis/v9, goose migrations        |
| Frontend    | React 18 + TypeScript, Vite, Tailwind, React Router, React Query  |
| Database    | PostgreSQL 16                                                     |
| Cache/queue | Redis 7                                                           |
| Mail plane  | Postfix 3.x, Rspamd 4.x, ClamAV 1.4                               |
| Workers     | Python 3.12, pyzbar, Playwright/Chromium, Anthropic SDK           |
| MFA         | pquerna/otp (TOTP)                                                |
| CI/CD       | GitLab CI on a shell runner registered on `docker02`              |

---

## Quick start (local dev)

```bash
# 1. Generate secrets + .env
./scripts/bootstrap-env.sh
# Then review deploy/docker/.env and set POSTFIX_MYHOSTNAME/TLS values as needed.

# 2. Build + start
make up

# 3. Migrate + seed (prints generated admin password)
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml exec api /app/migrate up
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml exec api /app/migrate seed

# 4. UI → http://localhost:8080/
```

Make targets: `make build / test / lint / up / down / logs / ps / migrate / seed / check`.

---

## Production / shared dev (docker02)

Push to `main` and GitLab CI runs four stages on the `docker02` shell runner:

1. **check:go** — `go vet ./... && go test ./... -race -count=1`
2. **security:\*** — Semgrep, Gitleaks, TruffleHog, Dependency-Check, Bandit, Trivy repo/config scan, and Trivy container-image scans for every built service image
3. **deploy:docker02** — rsyncs source to `/home/debian/docker/sentinelmail-gateway/`, builds and starts the stack via Docker Compose, runs migrations + seed
4. **smoke:docker02** — hits `/healthz`, `/api/v1/healthz`, and `/api/v1/me` from localhost

First-deploy bootstrap: the deploy job writes `.env` with random secrets if it's missing, or copies a file-type CI variable `SMG_DOTENV_FILE` verbatim if you set one. Existing `.env` is never overwritten — secret rotation is a deliberate operator action.

Required CI/CD variables: none for the default bootstrap. Optional: `SMG_DOTENV_FILE` for a custom `.env`.

Runner needs `install`, `find`, `mv` in its sudoers (we use `sudo install -d -o gitlab-runner …` to create the runtime dir). No broader sudo needed. docker02 also provides the scanner CLIs used by the security stage: `semgrep`, `trivy`, `gitleaks`, `trufflehog`, `dependency-check`, and `bandit`.

Trivy runs with `--ignore-unfixed` for repo and container scans. That is a deliberate security policy: the pipeline still fails on HIGH/CRITICAL findings with an available fix, while vendor-unfixed distro packages remain visible in JSON artifacts for tracking. The Dockerfiles run package upgrades during build, so once Debian/Ubuntu/Alpine publish fixed packages the same pipeline starts enforcing them without carrying local OS forks.

The Caddy image is built from the upstream Caddy source tag instead of copying the official binary when the official image lags a patched transitive dependency. This preserves the same Caddy release behavior while allowing the pipeline to enforce fixed Go module versions.

### Public GitHub mirror

SentinelMail Gateway is released as GPLv3 open source. GitLab remains the canonical working repository for CI, security scans, docker02 deploys, and spam01 production deploys. GitHub is the public mirror and community intake point:

- Public repo: `https://github.com/arphost-com/SentinelMail-Gateway`
- License: GNU General Public License v3.0 or later; see [`LICENSE`](LICENSE)
- Bugs and feature requests: file a GitHub issue with version/commit, deployment mode, relevant logs, expected behavior, and actual behavior
- Fixes: open a GitHub pull request, or describe the bug in an issue so a maintainer can apply the fix in GitLab
- GitLab CI/CD files are intentionally excluded from the GitHub mirror; deployment stays private to GitLab.

To publish from GitLab to GitHub, add a masked/protected GitLab CI/CD variable named `GITHUB_PAT` with GitHub Contents read/write access to `arphost-com/SentinelMail-Gateway`. Then run **GitLab -> CI/CD -> Pipelines -> latest main pipeline -> `push:github`**. The job publishes a filtered public tree to GitHub and verifies `.gitlab-ci.yml` / `.gitlab/` are absent.

---

## Configuration

### Boot-time `.env`

These must exist before the API can read DB-backed settings, so they stay in `.env`:

| Variable                                         | Purpose                                                    |
| ---                                              | ---                                                        |
| `SMG_DATABASE_URL`                               | Postgres connection (built from POSTGRES_* in compose)     |
| `SMG_REDIS_URL`                                  | Redis connection                                           |
| `SMG_HTTP_ADDR`                                  | API bind (default `:8080`)                                 |
| `SMG_SESSION_SECRET`                             | Cookie session HMAC + MFA challenge signer (>= 32 bytes)   |
| `SMG_AUDIT_HMAC_KEY`                             | Audit-log tamper-evidence key (future use)                 |
| `SMG_INGEST_HMAC_KEY`                            | Shared with rspamd Lua + workers — empty disables ingest   |
| `SMG_ENV`                                        | `dev` → non-Secure cookies (plain HTTP); anything else → Secure |
| `POSTGRES_PASSWORD`                              | Postgres user password                                     |
| `RSPAMD_PASSWORD` / `RSPAMD_CONTROLLER_PASSWORD` | Rspamd web UI / controller auth                            |
| `ANTHROPIC_API_KEY`                              | Optional — switches AI scoring from heuristic to Claude    |
| `SMG_AI_MODEL`                                   | Optional — defaults to `claude-haiku-4-5-20251001`         |
| `POSTFIX_MYHOSTNAME` / `POSTFIX_MYNETWORKS`      | Postfix initial config (also configurable at runtime)      |
| `SMG_SMTP_LISTEN_IP`                             | Bind IP for SMTP (set to docker02's `10.10.10.93` when a system MTA holds 127.0.0.1:25) |

### Runtime (UI: Settings → System tab)

Editable from the UI without restart; lives in `system_settings`. Add a new key by appending to `internal/settings/settings.go::DefaultKeys` and seeding it in a new migration.

| Key                           | Type   | Default                                      |
| ---                           | ---    | ---                                          |
| `ui.brand_name`               | string | `SentinelMail Gateway`                       |
| `mail.hostname`               | string | `mx.example.com`                             |
| `mail.mynetworks`             | string | `127.0.0.0/8 10.0.0.0/8 172.16.0.0/12`       |
| `message.retention_days`      | int    | `90`                                         |
| `quarantine.default_action`   | enum   | `tag` (deliver/tag/quarantine/reject)        |

### Threat feeds (Settings → Threat feeds)

Per-feed enable, refresh interval, source URL, API key, and live status. Seeded: Spamhaus ZEN/DBL, SpamCop, URLhaus, OpenPhish (disabled by default — needs key). **Contract:** per-feed failure is a miss, never an error — mail flow never blocks on feed outage.

---

## REST API

All under `/api/v1`. Session cookie auth except where noted.

```
POST   /auth/login              { email, password }
POST   /auth/logout
POST   /auth/mfa/verify         { challenge, code }       (HMAC-signed; no cookie)
POST   /auth/mfa/setup          (returns QR PNG + secret)
POST   /auth/mfa/confirm        { code }
POST   /auth/mfa/disable        { code }
GET    /me

GET|POST|PATCH|DELETE  /orgs[/{id}]
GET|POST|PATCH|DELETE  /domains[/{id}]
GET|POST|PATCH|DELETE  /gateways[/{id}]
GET|POST|PATCH|DELETE  /policies[/{id}]
POST   /policies/resolve

GET    /quarantine
GET    /quarantine/{id}
POST   /quarantine/{id}/release
DELETE /quarantine/{id}

GET    /mail-logs
GET    /mail-logs/{id}
GET    /mail-logs/stats?window=24h

GET    /smtp-events              (admin; Postfix-only rejects/deferrals/TLS)

GET    /users
POST   /users
PATCH  /users/{id}
DELETE /users/{id}
POST   /users/{id}/password     { password }

GET    /system/settings         (admin)
GET    /system/settings/schema
PATCH  /system/settings         (super_admin)

GET    /threat-feeds            (admin)
PATCH  /threat-feeds/{feed}     (super_admin)

GET    /scan                    (tenant-scoped list)
POST   /scan                    { kind, payload, mail_log_id? }
GET    /scan/{id}

GET    /audit-log

# HMAC-authenticated (no session) — for rspamd + workers
POST   /mail/events
POST   /scan-callback/{id}/result
GET    /scan-callback/{id}/payload
```

---

## Auto-trigger pipeline (active by default)

When the rspamd container starts it loads `smg_ingest.lua` (baked into the image at `/etc/rspamd/lua.local.d/`). On every scanned message the Lua POSTs the metadata + body + URLs + image attachments to `/api/v1/mail/events`, signed with `SMG_INGEST_HMAC_KEY`.

The Go ingest handler:

1. Looks up the recipient's domain → organization
2. Resolves the effective policy and decides disposition (deliver / tag / quarantine / reject)
3. Writes `mail_logs` and, if quarantined, `quarantine_entries`
4. Fans out scan jobs:
   - **inbound** → one `ai` scan (subject + body)
   - **inbound + image attachments** → one `qr` scan per image (cap 5)
   - **inbound + URLs** → one `sandbox` scan on the first URL
   - **outbound** (SASL-authed sender) → one `outbound` scan

Caps inline: 16 KB body for AI, 5 attachments at 2 MB each for QR, 1 URL for sandbox. Errors during scan enqueue surface in the API response but never fail the mail ingest.

**Safety:** when `SMG_INGEST_HMAC_KEY` is empty, the Lua snippet detects it on startup and no-ops. No 401-storm in the api log, no impact on mail flow.

---

## Authentication + MFA

- Argon2id passwords (m=64MiB, t=3, p=2, 32-byte key, 16-byte salt)
- Session cookie: 32-byte random token; only `sha256(token)` stored in `sessions`. `HttpOnly`, `SameSite=Lax`, `Secure` outside dev. 12-hour TTL. Logout / password reset / MFA disable revoke immediately.
- TOTP MFA: enrollment in Settings → Account. Login flow returns `mfa_required` + 5-min HMAC-signed challenge; client posts to `/auth/mfa/verify` with the challenge + 6-digit code to complete.
- Tier rule: an actor can only assign roles at or below their own — `org_user < org_admin < msp_admin < super_admin`.

---

## Repo layout

```
SentinelMail-Gateway/
├── cmd/
│   ├── api/                  HTTP server + healthcheck CLI
│   └── migrate/              goose-driven CLI (also runs `seed`)
├── internal/
│   ├── audit/                /api/v1/audit-log + Write/WriteAsync helpers
│   ├── auth/                 Argon2id, sessions, RBAC, TOTP MFA
│   ├── config/               env-based bootstrap config
│   ├── db/                   pgxpool wiring
│   ├── domains/              /api/v1/domains
│   ├── gateways/             /api/v1/gateways
│   ├── httpapi/              chi router + middleware
│   │   └── httpx/            shared JSON helpers, pagination, error envelope
│   ├── mail/                 /api/v1/mail/events + spawnScans
│   ├── maillogs/             /api/v1/mail-logs + /stats
│   ├── migrations/sql/       embedded goose migrations (00001-00004)
│   ├── orgs/                 /api/v1/orgs
│   ├── policies/             /api/v1/policies + resolver
│   ├── quarantine/           /api/v1/quarantine
│   ├── scan/                 /api/v1/scan + worker callback (HMAC)
│   ├── settings/             /api/v1/system/settings (schema-driven)
│   ├── tenant/               org-scoping helper (recursive CTE)
│   ├── threatfeed/           pluggable feed registry + DNS RBL + URLhaus + handler
│   └── users/                /api/v1/users + password reset
├── web/                      React + TS + Vite + Tailwind SPA
│   └── src/
│       ├── api/              fetch wrapper
│       ├── auth/             AuthProvider + useAuth (handles MFA challenge)
│       ├── components/ui/    Button, Input, Card, Table, Modal, DataTable, Field
│       ├── components/       ErrorBoundary
│       ├── layouts/          AppLayout (sidebar + 11 sections)
│       ├── pages/            Dashboard, Quarantine, Threats, AuditLog, Docs,
│       │                     Orgs, Domains, Gateways, Policies, Users,
│       │                     Settings, Login
│       └── theme/            ThemeProvider + 6 themes
├── workers/
│   ├── sandbox/              light worker: qr / ai / outbound
│   │   └── handlers/         pluggable per-kind handlers
│   └── sandbox-worker/       heavy worker: sandbox (Playwright)
├── deploy/docker/
│   ├── docker-compose.yml    dev compose (build: directives)
│   ├── .env.example          dev .env reference
│   ├── api/Dockerfile        Go multi-stage (non-root)
│   ├── web/Dockerfile        Node build + nginx runtime (non-root)
│   ├── worker/Dockerfile     Python (non-root, libzbar0)
│   ├── sandbox-worker/Dockerfile  Playwright + Chromium base image
│   ├── postfix/              Dockerfile + main.cf + master.cf + entrypoint
│   └── rspamd/               Dockerfile + local.d/ + lua.local.d/ + entrypoint
├── .gitlab-ci.yml            shell-runner pipeline (check → security → deploy → smoke → publish)
├── Makefile
├── README.md                 this file
├── CLAUDE.md                 agent guidance for future Claude Code sessions
└── SentinelMail_Gateway_Build_Spec.md   original product spec
```

---

## Operator setup (one-time post-deploy)

After the first pipeline succeeds and the stack is up:

1. **Sign in.** The seeded admin password is in the deploy job log. Rotate immediately (Users → Reset password on yourself, or delete + reseed — see in-app Docs → MFA → "Lost device").
2. **Enable MFA on the admin.** Settings → Account → Enable two-factor.
3. **Register your first managed domain.** Sidebar → Domains → `+ New domain`. Without this, inbound mail for the domain is rejected as "unknown recipient domain" by the ingest.
4. **(Optional) Enable Claude AI scoring.** Drop `ANTHROPIC_API_KEY=sk-ant-...` into `/home/debian/sentinelmail-gateway/deploy/docker/.env` and restart the worker:
   ```bash
   sudo nano /home/debian/sentinelmail-gateway/deploy/docker/.env
   sudo -u gitlab-runner docker compose --env-file /home/debian/sentinelmail-gateway/deploy/docker/.env -f /home/debian/sentinelmail-gateway/deploy/docker/docker-compose.yml restart worker
   ```
5. **Point DNS at the gateway.** Set MX records for your domain to docker02 (or whichever host you deployed on), with the next-hop gateway you configured under Sidebar → Gateways.

That's it. From here Rspamd auto-trigger fires on every message and the in-app **Docs** page (sidebar) explains day-to-day use.

---

## Security posture

- All Dockerfiles run non-root with `HEALTHCHECK`. Postfix is a documented exception (must bind 25/587 + manage queue dirs; privsep internally to `postfix` user) — covered by `.trivyignore` and Dockerfile comments.
- Dependency CVEs cleared at last scan: pgx, x/crypto, go-redis, chi, vite all on patched versions. `npm audit --omit=dev` → 0 vulnerabilities.
- Argon2id passwords, sha256-hashed sessions, HMAC-auth on all rspamd / worker callbacks, fixed `Host: api` header on the nginx proxy, tenant-scoped reads/writes gated by `internal/tenant.Scope`.
- Threat-feed lookups downgrade per-feed errors to misses — mail flow never blocks on feed outage (covered by tests).
- TOTP MFA available per-user; admin password reset revokes all the target's other sessions.
- nginx re-resolves `api` every request via `resolver 127.0.0.11 valid=10s` so api container restarts don't leave the proxy hitting a dead IP.

---

## Troubleshooting

### Pipeline failed at deploy
Check `sudo journalctl -u gitlab-runner --since '15 min ago' | grep sentinelmail | grep job-status`. The most common single-cause failures we've hit and fixed:

| Symptom | Cause | Fix |
|---|---|---|
| 502 from nginx after redeploy | nginx cached api's old IP | Already fixed by the `resolver + variable proxy_pass` pattern. If it recurs, restart the `web` container. |
| Postfix crash-loops `missing 'postlog'` | Postfix 3.4+ requires `postlog` in master.cf | Fixed in `deploy/docker/postfix/master.cf`. |
| Smoke job fails in <1s | `.env` shell-source choked on spaces | Quote multi-word values like `POSTFIX_MYNETWORKS=…`. Bootstrap heredoc does. |
| Rspamd crash-loops `module 'cjson.safe' not found` | Lua snippet using cjson | Fixed; uses rspamd's bundled `ucl` now. |
| Migration 00002 fails `null value in "organization_id"` | Composite PK rejected NULL | Fixed; surrogate `id` PK + partial unique indexes. |
| Login returns 200 but UI bounces back | Browser dropped `Secure` cookie over HTTP | Set `SMG_ENV=dev` in `.env`. |
| Web container shows "unhealthy" but serves fine | wget hit `::1`, nginx listens IPv4-only | Fixed; healthcheck uses `127.0.0.1`. |

### Threats page shows scans `queued` forever
Worker container isn't picking up. `docker compose logs worker / logs sandbox`. Usually `SMG_INGEST_HMAC_KEY` missing from the worker env. Check both compose env blocks pass it.

### Dashboard always shows zeros
No mail processed yet (no real mail flowing) **or** recipient domain isn't registered. Add the domain on the Domains page and re-send.

### AI scan shows `engine: heuristic-fallback`
`ANTHROPIC_API_KEY` isn't set. See Operator setup step 4 above.

### Threat feed shows `error` in Settings
See `last_refresh_err`. Usually a network blocker (Spamhaus rate-limit, no outbound HTTPS). Mail flow continues either way.

---

## License

SentinelMail Gateway is free software released under the GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
