# SentinelMail Role Guides

Plain-English help for each kind of user. These are the same ideas that should appear in the in-app **Docs** page so customers can use SentinelMail without reading source code.

For customer onboarding handoff, use [customer-quick-start.md](customer-quick-start.md) or the printable [customer-quick-start.pdf](customer-quick-start.pdf).

## Product Placement

SentinelMail can be sold two ways:

- **Onsite / customer-owned:** the customer runs it on their own VPS, dedicated server, or private server. They point their MX records at that server and forward clean mail to their existing mail server.
- **Direct internet / hosted MSP:** ARPHost or an MSP runs the internet-facing gateway and creates one organization per customer.

It is **not** a shared-hosting application. It needs Docker, persistent volumes, public SMTP and HTTPS ports, DNS/MX control, TLS certificate storage, mail queues, logs, and backups. Those controls are required for security and reliable mail delivery.

## End User

Use this if you only need to check your own email security.

What you can do:

- Sign in and change your password.
- Turn on two-factor authentication.
- See your own quarantined messages.
- Release a message if it is safe.
- Delete a quarantined message if it is junk.
- See your own mail logs and audit activity.

What you cannot do:

- You cannot change domains, policies, gateways, or other users.
- You cannot see other people's mail unless an admin gives you a higher role.

Daily workflow:

1. Open **Quarantine**.
2. Review messages marked `held`.
3. Click **Details** if you need to inspect sender, subject, score, or threat type.
4. Click **Release** only for mail you recognize and expect.
5. Click **Delete** for spam or phishing.

## Organization Admin

Use this if you manage one company or one tenant.

What you can do:

- Add and manage your organization's domains.
- Add downstream gateways, such as Mailcow, Exchange, Microsoft 365, Google Workspace, or Postfix.
- Manage policies for spam thresholds, quarantine thresholds, reject thresholds, greylisting, and DMARC behavior.
- Create users in your organization.
- Reset passwords and disable user accounts.
- View quarantine, mail logs, reports, threats, SMTP events, and audit entries for your organization.

First setup checklist:

1. Open **Domains** and add every domain that should receive mail through SentinelMail.
2. Open **Gateways** and add the real destination mail server for each domain.
3. Open **Policies** and start with conservative thresholds.
4. Open **Users** and create end users or other org admins.
5. Send a test message and confirm it appears in **Mail logs**.
6. Review **Quarantine** before lowering thresholds.

## MSP Admin

Use this if you manage multiple customer organizations.

What you can do:

- Create and manage child customer organizations.
- Operate domains, gateways, policies, users, quarantine, mail logs, threats, SMTP events, and reports across your customer subtree.
- Delegate customer admins while keeping tenant data separated.

Safe MSP workflow:

1. Create one organization per customer.
2. Add only that customer's domains to that customer organization.
3. Create a customer `org_admin` user for day-to-day management.
4. Keep MSP staff as `msp_admin` users.
5. Use reports and mail logs to answer customer questions without mixing customer data.

## Super Admin

Use this if you run the whole SentinelMail installation.

What you can do:

- See and manage every organization.
- Edit system-wide settings.
- Configure threat feeds.
- Manage all users.
- Impersonate users for support.
- Review all audit logs, SMTP events, mail logs, threats, reports, and quarantine.
- Deploy updates and verify production health.
- Triage public GitHub issues/PRs and publish accepted GitLab updates with the manual `push:github` job.

Production checklist:

1. Keep `.env` backed up securely.
2. Keep `SMG_INGEST_HMAC_KEY`, session secrets, audit keys, Postgres passwords, and Rspamd passwords private.
3. Confirm Caddy `/data` and `/config` volumes persist across deploys so TLS certificates are reused.
4. Keep DNS and MX records documented for every customer domain.
5. Review GitLab scanner results before production deploys.
6. Run smoke tests after every deploy.
7. Publish public updates with `push:github` only after GitLab CI and docker02 smoke pass.

## What Each Page Means

| Page | Purpose |
| --- | --- |
| Dashboard | Quick view of processed, delivered, quarantined, rejected, inbound, outbound, and verified phishing counts. |
| Mailbox | End-user mailbox-style view for messages the current user can see. |
| Mail logs | Searchable history of processed messages and dispositions. |
| Quarantine | Held messages waiting for release or deletion. |
| Threats | Background QR, sandbox, AI, and outbound compromise scan results. |
| SMTP events | Postfix-only rejects, TLS failures, downstream deferrals, and events that may happen before a message becomes a mail log. |
| Reports | Clickable summaries and charts that drill into matching mail logs. |
| Organizations | Tenant records. Usually one per customer. |
| Domains | Domains SentinelMail is allowed to accept mail for. |
| Gateways | Downstream mail servers where clean mail is delivered. |
| Policies | Thresholds and enforcement behavior. |
| Users | Account management and role assignment. |
| Audit log | Security-relevant activity history. |
| Settings | Personal settings, MFA, theme, system settings, and threat feeds. |

## Simple Safety Rules

- If you do not recognize a sender or domain, do not release the message.
- If a message asks for passwords, payment, gift cards, MFA codes, or urgent banking changes, treat it as suspicious.
- If a real customer complains that mail is missing, check **Mail logs**, **Quarantine**, then **SMTP events** in that order.
- If there is no mail log, the message may have been rejected before ingest; check **SMTP events**.
- If SentinelMail is deployed onsite, the customer must control DNS, firewall, Docker, volumes, backups, and mail routing.
