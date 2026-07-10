# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Current State

This repo is an active SentinelMail Gateway implementation. It now includes a Go API, React/Vite frontend, Docker Compose deployment, Postfix/Rspamd/ClamAV mail plane, Python workers, PostgreSQL migrations, GitLab CI, and production deploy scripts. Do not treat it as spec-only.

Use the current code and docs as source of truth:

- `README.md` for architecture, API, CI/CD, and dev quickstart.
- `docs/install.md` for production installs.
- `docs/use.md` and `docs/role-guides.md` for role-based operator/end-user guidance.
- `deploy/docker/docker-compose.yml` for the canonical runtime stack.
- `internal/migrations/sql/` for schema history.

The parent repo's `../AGENTS.md` (arphost-com root) carries the global rules: security coding guidelines (XXE, SQLi, XSS, crypto), Docker hardening (non-root, HEALTHCHECK), SSH server map (dev, docker02, app1), GitLab dependency proxy usage, and the `Co-Authored-By: BarryBot` commit footer. Follow those — they are not duplicated here.

## Product Shape

SentinelMail Gateway is a self-hosted, **multi-tenant** anti-spam / anti-phishing / email-security gateway that sits in front of one or many customer mail servers (Mailcow, Postfix, Exchange, M365, Google Workspace, generic SMTP). It must support both single-site and MSP deployments with delegated administration.

## Target Architecture

Inbound pipeline (from spec):

```
Internet → SMTP Gateway → SPF/DKIM/DMARC → Rspamd → Threat Intelligence
        → AI Analysis → Policy Engine → Deliver / Reject / Quarantine
```

Three-tier process model:

- **Backend (Go)** — SMTP gateway, policy engine, REST API at `/api/v1`, RBAC, MFA-ready, audit logging. Talks to PostgreSQL (state) and Redis (rate/queue/cache).
- **Mail-plane sidecars** — Postfix (MTA), Rspamd (scoring), ClamAV (AV). The Go service orchestrates policy and quarantine decisions; the MTA/Rspamd stack does the per-message work.
- **Python workers** — out-of-band analysis: Playwright browser sandbox, OCR / QR decoding, link sandboxing. These are async consumers, not in the SMTP hot path.
- **Frontend** — React + TypeScript + Tailwind + shadcn/ui. Dashboard sections: Dashboard, Organizations, Domains, Gateways, Policies, Quarantine, Threats, Reports, Settings.

When making architectural choices, preserve the **MTA ↔ scoring ↔ async-analysis** separation — moving sandboxing or AI calls inline will block the SMTP pipeline.

## Multi-tenancy Model

Tenancy is a first-class concern, not a retrofit. Every domain, gateway, policy, quarantine entry, mail log, and report belongs to an organization. Delegated admins must only see their org's data. Design schemas, API endpoints, and UI list views with org scoping from day one — do not build "single-tenant first, add tenancy later." (See `../arpvpnpro/AGENTS.md` for a sibling project that had to retrofit this and the friction it caused.)

## Threat Intelligence Sources (must integrate)

Spamhaus ZEN, Spamhaus DBL, SpamCop SCBL, URLhaus, OpenPhish, SURBL, URIBL. Treat each as a pluggable feed with its own refresh cadence, cache TTL in Redis, and graceful-degradation behavior when the feed is unreachable — do not let a single feed outage block mail flow.

## Detection Capabilities (must cover)

QR phishing, homoglyph domains, punycode, brand impersonation, newly-registered domains, HTML smuggling, credential harvesting, executive impersonation, BEC. Several of these (QR, homoglyph, brand impersonation) are MVP 2, not MVP 1 — see roadmap.

## MVP Roadmap (build in this order)

- **MVP 1** — SMTP gateway, Rspamd integration, quarantine, dashboard, policy engine, threat feeds, Docker Compose deployment.
- **MVP 2** — QR scanning, browser sandbox, AI detection, outbound compromise detection.
- **MVP 3** — Link rewriting, SSO, reporting, billing hooks, multi-node clustering.

Do not pull MVP 2/3 features into MVP 1 work without an explicit ask — the spec is deliberately phased so MVP 1 can ship.

## Accessibility

WCAG 2.2 AA is a hard requirement, not aspirational. Six themes are required (Dark, Light, High Contrast Dark, High Contrast Light, Colorblind Safe, Large Text) plus Reduced Motion. Every new UI control needs keyboard nav, ARIA labels, focus indicator, and a tooltip if it exposes an advanced setting. Don't ship UI without this — it will have to come out and go back in.

## Deployment Targets

Docker Compose is the canonical deployment (per spec and per arphost-com convention). When the scaffolding lands, follow the parent repo's rules: services accessed by **IP, not hostname**; non-root containers; HEALTHCHECK on every image; GitLab dependency proxy for base images in CI. Test on `docker02` before anything goes near production.

`spam01` production checkout path is `/home/debian/sentinelmail-gateway`; production Compose path is `/home/debian/sentinelmail-gateway/deploy/docker`.
