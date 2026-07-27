# Screenshot Capture Guide

Use this guide when adding customer-facing screenshots to `docs/role-guides.md` or the in-app Docs page.

## Required Environment

Screenshots must come from a populated, non-production-safe demo organization or a sanitized production-support session. Do not capture real customer message bodies, addresses, secrets, API keys, session cookies, MFA QR codes, or abuse-report previews.

Recommended capture state:

| Screenshot | Route | Required visible state |
| --- | --- | --- |
| Dashboard overview | `/dashboard` | Non-zero processed, delivered, quarantined, rejected, inbound, outbound, and confirmed-phishing counts. |
| Users management | `/configuration/users` | At least one `org_user`, one `org_admin`, and one disabled or invited user if available. |
| Quarantine detail | `/quarantine` | Sanitized held message with Details available, no real body text or customer addresses. |
| Mail logs drilldown | `/mail-logs` | Sanitized filtered results showing disposition and score columns. |

## Capture Rules

- Use a 1440px-wide desktop viewport for primary docs screenshots.
- Use the Light theme unless the screenshot is specifically about accessibility or theme behavior.
- Crop to the app content area when possible, but keep enough sidebar/header context for users to map the screenshot to the product.
- Save files under `docs/screenshots/` using stable lowercase names such as `dashboard-overview.png` and `users-management.png`.
- Keep images under 300 KB where practical.
- Add meaningful alt text in Markdown and in-app docs.
- Rebuild the frontend after wiring screenshots into `web/src/pages/DocsPage.tsx`.

## Current Status

No approved populated screenshot source is available in this checkout. The docs currently use textual screen references instead of fabricated or empty screenshots. Add real images only after a populated, sanitized environment is available.
