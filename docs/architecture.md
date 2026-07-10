# Architecture

Component map for engineers. For the operator + admin view, see [use.md](use.md). For the REST API + repo layout, see the main [README.md](../README.md).

```
                     Internet
                        │
              ┌─────────┼─────────────┐
              ▼                       ▼
         port 25 (SMTP)         port 80/443 (HTTPS)
              │                       │
              ▼                       ▼
        ┌───────────┐           ┌───────────┐
        │  Postfix  │           │   Caddy   │
        └────┬──────┘           └─────┬─────┘
             │ milter                 │ reverse_proxy
             ▼                        ▼
        ┌────────────┐          ┌───────────┐
        │   Rspamd   │──CL──┐   │    web    │ nginx + React SPA
        │  +AV+RBLs  │      │   └─────┬─────┘
        │  +Lua post-│      │         │ /api/ proxy
        │   filter   │      │         ▼
        └─────┬──────┘      │   ┌───────────┐
              │ POST        │   │    api    │ Go (chi)
              │ /mail/events│   │           │
              ▼             │   │  policy + │
        ┌─────────────────────────────────┐ │
        │              api                │ │
        │  /api/v1/*  +  /mail/events     │ │
        │                                 │ │
        │  spawnScans()                   │ │
        └────┬──────────────┬─────────────┘ │
             │              │               │
             ▼              ▼               │
        ┌─────────┐    ┌──────────┐         │
        │ Postgres│    │  Redis   │         │
        │ 16      │    │  smg:    │         │
        │ org/    │    │  scan_   │         │
        │ users/  │    │  jobs    │         │
        │ mail_   │    │  smg:    │         │
        │ logs/…  │    │  scan_   │         │
        └─────────┘    │  jobs_   │         │
                       │  sandbox │         │
                       └────┬─────┘         │
                            │               │
                ┌───────────┼─────┐         │
                ▼                 ▼         │
        ┌─────────────┐    ┌─────────────┐  │
        │   worker    │    │  sandbox-   │  │
        │  (light)    │    │   worker    │  │
        │ qr / ai /   │    │ Playwright +│  │
        │ outbound    │    │  Chromium   │  │
        └─────┬───────┘    └─────┬───────┘  │
              │ POST result      │ POST result
              └──────────────────┴──────────┘
                  /scan-callback/{id}/result
                  (HMAC-signed)
```

## Why this shape

- **Two reverse proxies (Caddy + nginx)** are intentional: nginx serves the React SPA from disk and proxies `/api/*` to the Go api. Caddy does TLS termination + redirect. Splitting means Caddy can rotate certs / reload without touching the SPA-serving layer, and the nginx config can change without touching TLS.
- **Two worker images** because Playwright + Chromium adds ~1 GB. Keeping it isolated in `sandbox-worker` lets the light worker (qr/ai/outbound) stay ~200 MB and reboot in seconds. Crashes in one don't affect the other.
- **Two Redis queues** (`smg:scan_jobs`, `smg:scan_jobs_sandbox`) because BLPOP doesn't let a worker "skip" a job it can't handle — separate queues are cleaner than a poll-and-requeue dance.
- **HMAC-authenticated worker callbacks** because the workers don't have cookies. Same `SMG_INGEST_HMAC_KEY` that rspamd uses.
- **Tenant-scoped reads everywhere** via `internal/tenant.Scope`. Org_user / org_admin / msp_admin / super_admin scope is enforced in every handler, not just the auth middleware.
- **Postfix starts as root inside its container** because a real MTA must bind privileged SMTP ports 25/587 and manage queue directories owned by the package-created `postfix` / `postdrop` users. This is the only container-level root exception. Postfix then uses its own privilege separation model: long-running SMTP, cleanup, queue, and delivery workers run under unprivileged Postfix users, while Docker volumes keep queue state isolated to the stack. Deploy this on a VPS or dedicated server where you control Docker and firewall policy; shared hosting does not provide a secure boundary for an internet-facing MTA.

## Data flow for inbound mail

1. Sender's MTA opens TCP 25 to your public IP
2. Postfix accepts after SPF/DKIM/DMARC/RBL checks via Rspamd milter
3. Rspamd Lua postfilter POSTs the event (subject, body, URLs, image attachments) to `/api/v1/mail/events` signed with `SMG_INGEST_HMAC_KEY`
4. Go api:
   - Verifies the HMAC
   - Looks up recipient domain → organization
   - Resolves applicable policy (domain → org tree walk → DB default → hardcoded safe fallback)
   - Decides disposition (`delivered` / `tagged` / `quarantined` / `rejected`)
   - Writes `mail_logs` row, plus `quarantine_entries` if held
   - Fan-out: enqueues per-kind scan jobs to Redis
     - inbound + body → 1 `ai` scan
     - inbound + image attachments → up to 5 `qr` scans
     - inbound + URLs → 1 `sandbox` scan
     - outbound (SASL-authed) → 1 `outbound` scan
5. Workers pop from Redis, do the work, POST result back via `/api/v1/scan-callback/{id}/result`
6. UI shows the result under **Threats**

Postfix's actual delivery to the downstream MX happens after Rspamd accepts; the scan results inform future policy decisions but don't gate the current message (the scan is async by design).

## Data flow for the UI

1. Browser → Caddy `:443` → reverse_proxy `:8080` (nginx)
2. nginx serves SPA from disk; `/api/*` → reverse_proxy `api:8080`
3. api: cookie session middleware → tenant scope → handler
4. handler reads/writes Postgres, returns JSON
5. Sensitive callbacks (worker, rspamd) bypass the session middleware and use HMAC instead

## Tech versions

| | |
| --- | --- |
| Go | 1.25 |
| chi | v5.2 |
| pgx | v5.9 |
| go-redis | v9.19 |
| pquerna/otp | v1.4 |
| React | 18.3 |
| Vite | 8.0 |
| Tailwind | 3.4 |
| Postgres | 16-alpine |
| Redis | 7-alpine |
| Postfix | 3.x (Debian bookworm) |
| Rspamd | 4.0 |
| ClamAV | 1.4 |
| Caddy | 2-alpine |
| Python (workers) | 3.12 |
| Playwright | 1.49 (Microsoft base image) |

All deps tracked in `go.mod` / `web/package.json` / `workers/*/requirements.txt`.

## See also

- Main [README.md](../README.md) for repo layout, REST API, dev setup
- [install.md](install.md) for production setup
- [troubleshoot.md](troubleshoot.md) for failure modes
