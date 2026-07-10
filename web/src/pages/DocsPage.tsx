import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { Card, CardBody } from "../components/ui/Card";

interface DocSection {
  id: string;
  title: string;
  body: JSX.Element;
}

/**
 * Authoring guidance for future contributors: keep each section tight (one
 * scrollable screen ideally), prefer concrete examples to abstract prose,
 * and use the same vocabulary the UI uses ("Quarantine", "Threats", etc.)
 * so users can map docs to screens without translation.
 */
const SECTIONS: DocSection[] = [
  {
    id: "overview",
    title: "Overview",
    body: (
      <>
        <p>
          SentinelMail Gateway is a multi-tenant anti-spam, anti-phishing and email-security gateway
          that sits in front of one or more mail servers. It does the SMTP-side scoring (Postfix +
          Rspamd + ClamAV) and an async, deeper analysis layer (QR phishing, browser sandbox, AI
          scoring, outbound compromise heuristics) that runs in background workers.
        </p>
        <p className="mt-2">
          The UI you are in covers everything you need to operate the gateway: configuration
          (Organizations, Domains, Gateways, Policies, Users), day-to-day mail handling
          (Dashboard, Quarantine, Threats), and tenant settings (Settings → System, Threat feeds,
          Account).
        </p>
      </>
    ),
  },
  {
    id: "first-login",
    title: "First-time setup",
    body: (
      <>
        <ol className="list-decimal pl-5 space-y-1">
          <li>
            <strong>Sign in.</strong> The default admin is <code>admin@sentinelmail.local</code>;
            initial password is generated on the first deploy (printed to the CI job log; or use
            the rotation procedure in the repo README to reset it).
          </li>
          <li>
            <strong>Enable two-factor.</strong> Settings → Account → "Enable two-factor". Scan the
            QR code with any TOTP app (1Password, Authy, Google Authenticator) and enter the
            6-digit code to confirm. Next sign-in will prompt for it after the password.
          </li>
          <li>
            <strong>Create an Organization.</strong> Organizations are tenants — your own company is
            usually one; MSPs create one per customer. Sidebar → Organizations → "+ New".
          </li>
          <li>
            <strong>Register your Domains.</strong> Sidebar → Domains → add the domains you accept
            mail for. The Rspamd integration uses these to recognise inbound vs outbound and to
            scope mail-log entries to the right organization.
          </li>
          <li>
            <strong>Point MX at us.</strong> Direct your DNS MX records at the gateway host
            (default port 25). For test domains use a low-priority MX so you can fall back.
          </li>
        </ol>
      </>
    ),
  },
  {
    id: "plain-english-roles",
    title: "Plain-English role guides",
    body: (
      <>
        <p>
          SentinelMail is used in two common ways: onsite on a customer's own VPS/server, or as a
          direct internet-facing hosted/MSP gateway. It is not a shared-hosting app because it must
          control SMTP ports, Docker services, persistent volumes, mail queues, TLS certificates,
          logs, backups, DNS/MX routing, and firewall rules.
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="rounded border border-border bg-muted p-3">
            <h3 className="font-semibold">End user</h3>
            <p className="mt-1 text-sm text-subtle">
              Check your own quarantine, release mail you trust, delete junk, review your own mail
              logs, change your password, and manage two-factor authentication.
            </p>
          </div>
          <div className="rounded border border-border bg-muted p-3">
            <h3 className="font-semibold">Organization admin</h3>
            <p className="mt-1 text-sm text-subtle">
              Manage one company's domains, gateways, policies, users, quarantine, mail logs,
              threats, SMTP events, reports, and audit activity.
            </p>
          </div>
          <div className="rounded border border-border bg-muted p-3">
            <h3 className="font-semibold">MSP admin</h3>
            <p className="mt-1 text-sm text-subtle">
              Manage customer organizations in your subtree. Create one organization per customer,
              delegate customer admins, and keep each customer's mail data separated.
            </p>
          </div>
          <div className="rounded border border-border bg-muted p-3">
            <h3 className="font-semibold">Super admin</h3>
            <p className="mt-1 text-sm text-subtle">
              Operate the whole gateway: all tenants, system settings, threat feeds, users,
              impersonation for support, production health, scanner gates, and security controls.
            </p>
          </div>
        </div>
        <p className="mt-3 text-sm">
          Simple support path: if mail is missing, check <strong>Mail logs</strong>, then{" "}
          <strong>Quarantine</strong>, then <strong>SMTP events</strong>. If there is no mail log,
          the message may have been rejected before ingest.
        </p>
        <p className="mt-3 text-sm">
          Customer handoff:{" "}
          <a
            className="text-accent underline"
            href="/docs/customer-quick-start.pdf"
            download
          >
            download the customer quick-start PDF
          </a>
          .
        </p>
      </>
    ),
  },
  {
    id: "concepts",
    title: "Concepts",
    body: (
      <>
        <dl className="space-y-2">
          <div>
            <dt className="font-semibold">Organization</dt>
            <dd className="text-subtle text-sm">
              A tenant. Has its own users, domains, policies, quarantine, audit log. Organizations
              can have children (parent_id) — MSP admins see their org + descendants.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Domain</dt>
            <dd className="text-subtle text-sm">
              A mail domain you manage (e.g. <code>acme.com</code>). Determines which org owns an
              inbound message.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Gateway</dt>
            <dd className="text-subtle text-sm">
              The downstream MX target per domain (Mailcow, Postfix, Exchange, M365, Google
              Workspace, generic SMTP). Lower priority wins.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Policy</dt>
            <dd className="text-subtle text-sm">
              Spam / quarantine / reject thresholds + DMARC enforcement + greylisting toggle.
              Resolved per-message as: domain-level → org-tree walk → default → hardcoded safe
              fallback.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Scan (Threats page)</dt>
            <dd className="text-subtle text-sm">
              Async per-message analysis: QR code decoding, browser sandbox, AI scoring, outbound
              BEC heuristic. Auto-triggered by Rspamd on every inbound message; UI also lets
              admins submit a one-off scan.
            </dd>
          </div>
        </dl>
      </>
    ),
  },
  {
    id: "quarantine",
    title: "Quarantine",
    body: (
      <>
        <p>
          When a message scores at or above the policy's <em>quarantine</em> threshold, the
          policy action decides whether it is delivered, tagged, held, or rejected. The
          Quarantine page lists messages currently <code>held</code>{" "}
          (filter to <code>released</code> / <code>deleted</code> / <code>expired</code> if you
          need history).
        </p>
        <p className="mt-2"><strong>Actions:</strong></p>
        <ul className="list-disc pl-5 space-y-1">
          <li><strong>Release</strong> flips state to <code>released</code> (re-injection into the
            downstream MX is wired by the worker; if a release sits "released" without delivery,
            check the worker logs).</li>
          <li><strong>Delete</strong> marks the row <code>deleted</code> — the .eml blob in object
            storage stays until the inbox and quarantine retention window expires.</li>
        </ul>
        <p className="mt-2">
          <strong>End-user self-service:</strong> users with role <code>org_user</code> see only
          messages addressed to their own address; they can release/delete those without admin
          help.
        </p>
      </>
    ),
  },
  {
    id: "threats",
    title: "Threats (scan pipeline)",
    body: (
      <>
        <p>
          Four scan kinds run asynchronously in worker containers. Verdicts: <code>clean</code> /{" "}
          <code>suspicious</code> / <code>malicious</code> / <code>failed</code>.
        </p>
        <table className="text-sm w-full mt-2 border-collapse">
          <thead>
            <tr className="text-subtle text-left">
              <th className="pr-3 py-1">Kind</th>
              <th className="pr-3 py-1">What it does</th>
              <th className="py-1">Engine</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-t border-border">
              <td className="pr-3 py-1"><code>qr</code></td>
              <td className="pr-3 py-1">Decodes any QR/barcode in attached images; checks decoded URLs against URLhaus.</td>
              <td className="py-1">pyzbar + URLhaus feed</td>
            </tr>
            <tr className="border-t border-border">
              <td className="pr-3 py-1"><code>sandbox</code></td>
              <td className="pr-3 py-1">Loads a URL in headless Chromium; captures screenshot, redirects, password-input + cross-origin-form heuristics.</td>
              <td className="py-1">Playwright (separate worker)</td>
            </tr>
            <tr className="border-t border-border">
              <td className="pr-3 py-1"><code>ai</code></td>
              <td className="pr-3 py-1">Scores subject + body as phishing on 0..1. Heuristic keyword fallback if no Anthropic API key.</td>
              <td className="py-1">Claude (Haiku 4.5 default)</td>
            </tr>
            <tr className="border-t border-border">
              <td className="pr-3 py-1"><code>outbound</code></td>
              <td className="pr-3 py-1">Recipient fan-out, distinct-domain count, off-hours send, BEC subject keywords.</td>
              <td className="py-1">Pure-Python heuristics</td>
            </tr>
          </tbody>
        </table>
        <p className="mt-2">
          Auto-triggered on every Rspamd-scanned message. Use Threats → "+ Scan QR image" to
          submit a one-off without sending real mail.
        </p>
      </>
    ),
  },
  {
    id: "auto-trigger",
    title: "How auto-trigger works",
    body: (
      <>
        <p>
          The Rspamd container ships with a postfilter Lua script
          (<code>smg_ingest.lua</code>) that runs after every scan. It POSTs body + URLs + image
          attachments to <code>/api/v1/mail/events</code> with an HMAC signature.
        </p>
        <p className="mt-2">
          On receipt the API resolves the recipient's domain → organization → applicable policy,
          writes a mail_log entry, quarantines if over threshold, then fans out scan jobs:
        </p>
        <ul className="list-disc pl-5 space-y-1 mt-2">
          <li>Inbound message → one <code>ai</code> scan (subject + body).</li>
          <li>Inbound with image attachments → one <code>qr</code> scan per image (capped at 5).</li>
          <li>Inbound with URLs → one <code>sandbox</code> scan on the first URL.</li>
          <li>Outbound (SASL-authed sender) → one <code>outbound</code> scan.</li>
        </ul>
        <p className="mt-2">
          <strong>Activation:</strong> the snippet is built into the rspamd image and auto-loads
          on every container start. It no-ops gracefully if <code>SMG_INGEST_HMAC_KEY</code> is
          empty, so deployments missing the matching secret are safe.
        </p>
      </>
    ),
  },
  {
    id: "settings",
    title: "Settings",
    body: (
      <>
        <p>Four tabs on the Settings page:</p>
        <dl className="space-y-2 mt-2">
          <div>
            <dt className="font-semibold">Appearance</dt>
            <dd className="text-subtle text-sm">
              Theme picker (6 options including high-contrast and colorblind-safe) + reduce-motion
              toggle. Saved to localStorage per browser.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Account</dt>
            <dd className="text-subtle text-sm">
              Enable / disable two-factor (TOTP). Disabling requires a current code as proof of
              possession.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">System (admin only)</dt>
            <dd className="text-subtle text-sm">
              Brand name, MX hostname, trusted networks, inbox/quarantine retention, default action
              over threshold. New keys appear here automatically when added to the backend
              schema.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Threat feeds (admin only)</dt>
            <dd className="text-subtle text-sm">
              Per-feed enable, refresh interval, API key entry, live status (when last refreshed,
              ok/error/never). Takes effect within one refresh tick — no restart needed.
            </dd>
          </div>
        </dl>
      </>
    ),
  },
  {
    id: "users",
    title: "Users + roles",
    body: (
      <>
        <p>Four roles, in increasing privilege:</p>
        <ul className="list-disc pl-5 space-y-1">
          <li><code>org_user</code> — sees only their own quarantine + own audit entries; can change their own password.</li>
          <li><code>org_admin</code> — full read/write within their organization (Domains, Gateways, Policies, Users).</li>
          <li><code>msp_admin</code> — same as org_admin, plus can create child organizations and operate across them.</li>
          <li><code>super_admin</code> — sees and writes every org; only role that can edit default policies and System Settings.</li>
        </ul>
        <p className="mt-2">
          <strong>Tier rule:</strong> you can only assign roles at or below your own. Resetting
          another user's password revokes their other sessions immediately.
        </p>
      </>
    ),
  },
  {
    id: "mfa",
    title: "Two-factor (TOTP)",
    body: (
      <>
        <p>
          MFA uses standard time-based one-time passwords. Any authenticator app works — there's
          no SentinelMail-specific app.
        </p>
        <p className="mt-2"><strong>Enrolling:</strong> Settings → Account → "Enable two-factor".
          Scan the QR, enter the first 6-digit code to confirm.</p>
        <p className="mt-2"><strong>Logging in:</strong> after the password, the login screen
          asks for a code. The challenge expires in 5 minutes — if you let it sit, cancel and
          re-enter the password.</p>
        <p className="mt-2"><strong>Disabling:</strong> Settings → Account → enter a current code
          → "Disable two-factor".</p>
        <p className="mt-2"><strong>Lost device:</strong> a super_admin can DELETE the user and
          recreate them, or run an admin password reset (revokes sessions and clears MFA when
          combined with a future "force-disable-mfa" admin action — currently not in the UI;
          contact the maintainer for now).</p>
      </>
    ),
  },
  {
    id: "audit",
    title: "Audit log",
    body: (
      <>
        <p>
          Every notable change (login, logout, MFA enable/disable, MFA-completed login) writes a
          row to the append-only <code>audit_log</code> table. The Audit log page (sidebar)
          shows the most recent entries, filterable by action name or actor.
        </p>
        <p className="mt-2">
          The schema reserves a column for HMAC-chained tamper-evidence; that's wired in a
          follow-up. For now the rows are protected by the same DB ACLs as the rest of the
          tenant data.
        </p>
        <p className="mt-2"><strong>Common actions to look for:</strong></p>
        <ul className="list-disc pl-5 space-y-1">
          <li><code>auth.login</code>, <code>auth.logout</code></li>
          <li><code>auth.mfa.setup</code>, <code>auth.mfa.enrolled</code>, <code>auth.mfa.disabled</code>, <code>auth.mfa.login</code></li>
        </ul>
        <p className="mt-2 text-subtle text-sm">
          More CRUD events (user.create, policy.update, etc.) are queued for a follow-up — write
          sites need to be added in each handler. Open an issue if you need a specific one
          urgently.
        </p>
      </>
    ),
  },
  {
    id: "api",
    title: "REST API quick reference",
    body: (
      <>
        <p>All endpoints under <code>/api/v1</code>; session cookie auth except where noted.</p>
        <pre className="bg-muted p-3 rounded text-xs mt-2 overflow-x-auto">
{`POST   /auth/login              { email, password }
POST   /auth/logout
POST   /auth/mfa/verify         { challenge, code }      (no session — challenge proves password)
POST   /auth/mfa/setup          (returns QR PNG + secret)
POST   /auth/mfa/confirm        { code }
POST   /auth/mfa/disable        { code }
GET    /me                       current identity

GET|POST|PATCH|DELETE  /orgs[/{id}]
GET|POST|PATCH|DELETE  /domains[/{id}]
GET|POST|PATCH|DELETE  /gateways[/{id}]
GET|POST|PATCH|DELETE  /policies[/{id}]
POST   /policies/resolve       (debug: effective policy for a domain/org)

GET    /quarantine
GET    /quarantine/{id}
POST   /quarantine/{id}/release
DELETE /quarantine/{id}

GET    /mail-logs
GET    /mail-logs/{id}
GET    /mail-logs/stats?window=24h

GET    /smtp-events             (admin; Postfix-only rejects/deferrals/TLS)

GET    /users
POST   /users
PATCH  /users/{id}
DELETE /users/{id}
POST   /users/{id}/password    { password }

GET    /system/settings        (admin)
GET    /system/settings/schema
PATCH  /system/settings        (super_admin)

GET    /threat-feeds           (admin)
PATCH  /threat-feeds/{feed}    (super_admin)

GET    /scan
POST   /scan                   { kind, payload, mail_log_id? }
GET    /scan/{id}

GET    /audit-log

# HMAC-authenticated (no session)
POST   /mail/events
POST   /scan-callback/{id}/result
GET    /scan-callback/{id}/payload`}
        </pre>
      </>
    ),
  },
  {
    id: "open-source-updates",
    title: "Open source + updates",
    body: (
      <>
        <p>
          SentinelMail Gateway is GPLv3-or-later open source. GitLab is the canonical working
          repository for CI, security scans, docker02 deploys, and production deploys. GitHub is
          the public mirror where outside users can report bugs and send fixes.
        </p>
        <dl className="space-y-2 mt-2">
          <div>
            <dt className="font-semibold">Public repo</dt>
            <dd className="text-sm">
              <code>https://github.com/arphost-com/SentinelMail-Gateway</code>
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Bug reports</dt>
            <dd className="text-sm">
              Include the commit SHA, deployment type, sanitized logs, reproduction steps,
              expected behavior, and actual behavior. Do not post secrets, <code>.env</code>{" "}
              files, private message bodies, customer addresses, or raw quarantined mail.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Maintainer flow</dt>
            <dd className="text-sm">
              Apply accepted GitHub fixes in GitLab, let the normal GitLab checks and docker02
              smoke pass, then run the manual <code>push:github</code> pipeline job to publish
              the update back to GitHub.
            </dd>
          </div>
        </dl>
      </>
    ),
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting",
    body: (
      <>
        <dl className="space-y-3">
          <div>
            <dt className="font-semibold">Login returns 200 but I'm not signed in</dt>
            <dd className="text-sm">
              The session cookie has the <code>Secure</code> flag in production. If you're
              accessing the gateway over plain HTTP, browsers drop it silently. Either put TLS in
              front, or set <code>SMG_ENV=dev</code> in <code>.env</code> and restart api.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Threats page shows scans <code>queued</code> forever</dt>
            <dd className="text-sm">
              Worker container isn't picking up jobs. <code>docker compose logs worker</code> /{" "}
              <code>logs sandbox</code>. Most common cause: <code>SMG_INGEST_HMAC_KEY</code>{" "}
              missing on the worker container.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Dashboard always shows zeros</dt>
            <dd className="text-sm">
              No mail has been processed yet, or the recipient domain isn't registered. Add the
              domain on the Domains page; the next message will land in mail_logs.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">AI scan shows engine: heuristic-fallback</dt>
            <dd className="text-sm">
              Anthropic API key isn't set. Add <code>ANTHROPIC_API_KEY=sk-ant-...</code> to{" "}
              <code>.env</code> and restart the worker container to switch to Claude scoring.
            </dd>
          </div>
          <div>
            <dt className="font-semibold">Threat feed shows "error" status</dt>
            <dd className="text-sm">
              See the <code>last_refresh_err</code> message on Settings → Threat feeds. Most often
              a network blocker (Spamhaus DNS rate-limit, or no outbound HTTPS for URLhaus).
              Mail flow continues regardless — feeds never block delivery.
            </dd>
          </div>
        </dl>
      </>
    ),
  },
];

export function DocsPage() {
  const [active, setActive] = useState<string>(SECTIONS[0].id);
  const sectionRefs = useRef<Record<string, HTMLElement | null>>({});

  // Use IntersectionObserver to highlight whichever section is most-on-screen.
  // This is what gives the nav its "you are here" affordance as you scroll.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-20% 0px -60% 0px", threshold: [0, 0.25, 0.5, 0.75, 1] }
    );
    Object.values(sectionRefs.current).forEach((el) => el && observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const headings = useMemo(() => SECTIONS.map((s) => ({ id: s.id, title: s.title })), []);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-1">Documentation</h1>
      <p className="text-sm text-subtle mb-4">
        Living reference for the running gateway. See also the repo <code>README.md</code> for
        deploy / CI / architecture detail.
      </p>

      <div className="grid min-w-0 grid-cols-1 gap-6 lg:grid-cols-[14rem_minmax(0,1fr)]">
        <nav aria-label="Docs sections" className="lg:sticky lg:top-4 self-start text-sm">
          <ul className="flex flex-col gap-1">
            {headings.map((h) => (
              <li key={h.id}>
                <a
                  href={`#${h.id}`}
                  className={clsx(
                    "block rounded px-3 py-1.5 transition-colors",
                    active === h.id ? "bg-accent text-accentFg" : "text-fg hover:bg-muted"
                  )}
                >
                  {h.title}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div className="flex flex-col gap-6 max-w-3xl">
          {SECTIONS.map((s) => (
            <section
              key={s.id}
              id={s.id}
              ref={(el) => {
                sectionRefs.current[s.id] = el;
              }}
              aria-labelledby={`${s.id}-h`}
              className="scroll-mt-6"
            >
              <Card>
                <CardBody>
                  <h2 id={`${s.id}-h`} className="text-xl font-semibold mb-2">
                    {s.title}
                  </h2>
                  <div className="prose-sm">{s.body}</div>
                </CardBody>
              </Card>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
