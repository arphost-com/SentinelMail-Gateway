# SentinelMail Gateway — Build Specification

## Product Summary

Build SentinelMail Gateway, a self-hosted and multi-tenant anti-spam, anti-phishing, and email-security gateway designed to sit in front of one or many customer mail servers.

The platform supports:
- Single-site deployments
- MSP / hosted multi-tenant deployments
- Multiple inbound and outbound mail gateways
- Mailcow, Postfix, Exchange, Microsoft 365, Google Workspace, and generic SMTP backends
- Centralized policy management
- Accessible modern web UI
- Delegated administration

---

# Core Features

## Security Features

- AI phishing detection
- QR analysis
- Link sandboxing
- Domain-age scoring
- Live browser analysis
- Outbound compromise detection
- DMARC reject enforcement
- Aggressive phishing scoring
- SPF + DKIM enforcement
- Greylisting
- Spamhaus integration
- SpamCop integration
- URLhaus and OpenPhish support

---

# Architecture

## Inbound Flow

Internet
↓
SMTP Gateway
↓
SPF / DKIM / DMARC
↓
Rspamd
↓
Threat Intelligence
↓
AI Analysis
↓
Policy Engine
↓
Deliver / Reject / Quarantine

---

# Recommended Stack

## Backend

- Go
- PostgreSQL
- Redis
- Postfix
- Rspamd
- ClamAV

## Frontend

- React
- TypeScript
- Tailwind CSS
- shadcn/ui

## Workers

- Python
- Playwright
- OCR / QR decoding

---

# Accessibility

Implement WCAG 2.2 AA minimum.

Themes:
- Dark
- Light
- High Contrast Dark
- High Contrast Light
- Colorblind Safe
- Large Text
- Reduced Motion

Accessibility requirements:
- Keyboard navigation
- ARIA labels
- Screen reader support
- Focus indicators
- Adjustable text scaling
- Tooltips on all advanced settings

---

# Threat Intelligence

Support:
- Spamhaus ZEN
- Spamhaus DBL
- SpamCop SCBL
- URLhaus
- OpenPhish
- SURBL
- URIBL

---

# Detection Requirements

Detect:
- QR phishing
- Homoglyph domains
- Punycode
- Brand impersonation
- Newly registered domains
- HTML smuggling
- Credential harvesting
- Executive impersonation
- Business email compromise

---

# Quarantine Features

- Admin quarantine
- User quarantine
- Quarantine digests
- Release workflow
- Sender allow/block actions
- Safe previews
- Threat evidence display

---

# UI Requirements

Dashboard sections:
- Dashboard
- Organizations
- Domains
- Gateways
- Policies
- Quarantine
- Threats
- Reports
- Settings

UI goals:
- Easy for SMB users
- Powerful for MSPs
- Clear tooltips
- Minimal clutter
- Responsive design

---

# API

Base path:

/api/v1

Core endpoints:
- Authentication
- Organizations
- Domains
- Gateways
- Policies
- Quarantine
- Mail Logs
- Reports

---

# MVP Roadmap

## MVP 1
- SMTP gateway
- Rspamd integration
- Quarantine
- Dashboard
- Policy engine
- Threat feeds
- Docker deployment

## MVP 2
- QR scanning
- Browser sandbox
- AI detection
- Outbound compromise detection

## MVP 3
- Link rewriting
- SSO
- Reporting
- Billing hooks
- Multi-node clustering

---

# Codex Prompt

Build a production-ready self-hosted multi-tenant anti-spam and anti-phishing gateway platform.

Requirements:
- Go backend
- React frontend
- PostgreSQL
- Redis
- Postfix + Rspamd
- Docker Compose deployment
- REST API
- RBAC
- MFA-ready architecture
- Quarantine system
- Threat intelligence feeds
- QR phishing detection
- URL sandboxing
- Accessible multi-theme UI
- Audit logging
- Organization/domain policy support

Generate:
- Database migrations
- API documentation
- Seed data
- Unit tests
- UI tests
- Deployment documentation
