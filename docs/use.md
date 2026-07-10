# Day-to-day use

Quick reference for everyone who actually uses the gateway.

| You are | Read |
| --- | --- |
| End user (you receive mail for a managed domain) | [End user](#end-user) |
| Org admin (you manage one organization) | [Org admin](#org-admin) |
| MSP admin (you manage child organizations) | [MSP admin](#msp-admin) |
| Super admin (you run the whole gateway) | [Super admin](#super-admin) |

For an in-app reference, every signed-in user can click **Docs** in the sidebar.

For a simpler "what can I do?" version, read [role-guides.md](role-guides.md). It is written for customers and staff who do not need technical details.

For bugs in the public release, use the GitHub issue tracker and include sanitized logs plus the running commit SHA. Maintainers apply accepted fixes through GitLab, then publish them back to GitHub with the manual `push:github` pipeline job.

---

## End user

You're `org_user`. The sidebar shows the things you can do:

### Sign in + enable two-factor

1. Visit `https://your-host.example.com/`
2. Sign in with the credentials your admin gave you
3. **Settings → Account → Change password** — pick a real one
4. **Settings → Account → Enable two-factor** — scan the QR with any TOTP app (Authy, 1Password, Google Authenticator). Next sign-in will ask for the 6-digit code.

### Check your quarantined mail

**Sidebar → Quarantine.** Shows only messages addressed to you. State filter defaults to `held`.

- **Release** — message goes to your inbox (worker re-injects to your downstream MX).
- **Delete** — drops the row to `deleted` state. The original .eml is purged after the org's retention window.
- **Block sender / Block sender domain** — reports the quarantine item as spam, marks it handled, and adds a sender blocklist entry so future mail from the same sender or domain is blocked.
- **Purge expired** — admin-only cleanup that physically removes quarantine rows and stored message blobs whose retention window has expired. The default inbox and quarantine retention window is 90 days and can be set up to 365 days.

### Check what got delivered

**Sidebar → Mail logs.** Same scoping — only your mail. Filter by `disposition` (delivered / tagged / quarantined / rejected / deferred / failed). Click a row for the full Rspamd symbol set + headers.

### Audit your own activity

**Sidebar → Audit log.** Shows your own actions: logins, MFA changes, password changes. Useful for spotting an unexpected sign-in.

---

## Org admin

Everything end users see, plus:

### Manage your organization

**Sidebar → Org settings.** Per-org keys (brand name on outbound, support email, inbox/quarantine retention override, end-user digest frequency).

### Manage domains

**Sidebar → Domains.** Each domain you accept mail for needs a row here. Without one, mail to that domain is rejected as "unknown recipient domain" at ingest.

### Manage gateways

**Sidebar → Gateways.** Per-domain backend MX targets. Lower priority wins. The Postfix transport map uses these to deliver scanned mail.

### Manage policies

**Sidebar → Policies.** Thresholds and actions per domain (or per org as a default). Resolution: domain-specific → walk up org tree → DB default → hardcoded safe fallback.

The hardcoded fallback (spam ≥ 5, quarantine ≥ 10, reject ≥ 15, greylisting on) means the gateway is safe even before you create any policies.

### Manage users

**Sidebar → Users.** Create org_users for your organization. You can:

- Create with role at or below your own (`org_user`, `org_admin`)
- Reset anyone's password (revokes their other sessions)
- Disable accounts (sets `is_active=false`)

### Read other people's quarantine + mail logs

Within your org, you see everything — quarantine, mail-logs, threats, audit. End users see only their own slice.

---

## MSP admin

Everything org admins see, plus:

### Manage customer organizations

**Sidebar → MSP settings.** Shows your child orgs in a table. **+ New customer org** provisions one — name + slug (lowercase, hyphens). The new org has no users yet; create the first org_admin under **Sidebar → Users** with that org's UUID.

### Cross-org visibility

You see everything in your subtree via the same Domains / Gateways / Quarantine / Mail logs / Users pages. The tenant scope walks the parent chain so child-org data shows up automatically.

You can also create domains / gateways / policies on behalf of any child org — set the `organization_id` field in the create modal.

---

## Super admin

Everything else, plus the **`/system-settings`** entry that nobody else can see.

### Gateway-wide knobs

**Sidebar → System settings:**

- **Branding / Mail / Quarantine / TLS** keys — global defaults
- **Threat feeds** — toggle each on/off, set refresh interval, paste API keys

### Set up TLS

System settings → set `tls.mode` to `lets_encrypt`, `tls.hostname` to your public FQDN, `tls.acme_email` to a real address. Then on the host:

```bash
docker compose --env-file .env -f deploy/docker/docker-compose.yml restart caddy
```

(For now Caddy reads from `.env`, not the UI — flipping the UI keys persists them but you also need to copy the values to `.env`. The UI-to-Caddy autosync is queued for a follow-up.)

### Manage all users across all orgs

`/users` shows everyone in every org for super_admin. You can reset any password, disable any account, promote / demote roles within the tier rule (you can only assign roles at or below your own — for super_admin, that's any).

### When end users lose their MFA device

Fastest recovery is the `reset-admin` CLI — it resets the password *and* clears MFA in one call (despite the name, it works for any user):

```bash
docker compose exec -T api /app/migrate reset-admin alice@example.com
```

Hand the printed password to the user; they'll re-enroll MFA on next sign-in. (A "force-disable-mfa" admin action in the UI is queued for a follow-up.)

---

## Common workflows

### "I'm seeing spam that's getting through"

1. **Mail logs** → click the message → look at the `symbols` JSON — what did rspamd flag?
2. **Threats** → find the matching AI scan → verdict + score + reasoning
3. **Policies** → if rspamd score was 4 but threshold is 5, lower the org's `spam_threshold` to 3
4. (Optional) **Quarantine** → add the sender domain to your block list

### "A legitimate sender keeps being quarantined"

1. **Quarantine** → release the message
2. **Mail logs** → find similar past messages, check the Rspamd action that triggered it
3. **Policies** → either raise the org's `quarantine_threshold` (looser for everyone) or add the sender to a per-org allow list (cleaner)

### "I need to send mail TO our gateway from a different network"

You don't need to — internet senders just connect to MX 25. **But** if your own infrastructure (Mailcow, app server, office NAT) needs to relay outbound mail THROUGH the gateway, see [configure.md → `POSTFIX_MYNETWORKS`](configure.md#postfix_mynetworks--who-can-use-you-as-a-relay).

### "I want to test a new policy without sending real mail"

**Threats → + Scan QR image** lets you submit an ad-hoc QR scan with any PNG. For policy testing per se, the simplest is `swaks` from another host:

```bash
swaks --to test@yourdomain.com --from sender@spammy.example.com \
      --server your-host.example.com \
      --header "Subject: TEST PHISHING" \
      --body "Click here to reset your password immediately"
```

The AI handler will flag the keywords, the policy will react, you'll see the result in **Mail logs** within ~5s.

---

## See also

- [install.md](install.md) — first install
- [configure.md](configure.md) — settings reference
- [troubleshoot.md](troubleshoot.md) — what to do when something looks wrong
- In-app **Docs** sidebar entry — same content as this page, indexed
