# Phishing-brand intelligence

SentinelMail keeps phishing-brand intelligence in PostgreSQL instead of relying
only on code constants. The catalog stores:

- canonical brand name and slug;
- aliases used in display names, subjects, and message bodies;
- validated official sender/link domains;
- sensitive-context cues;
- protection state and priority;
- per-source rank, observation count, first/last seen, refresh time, source URL,
  and licensing notes.

The built-in catalog contains 144 independently curated protected profiles. A
brand must have validated official domains before it becomes an active
protection rule. Feed-only target names are stored as observations but remain
inactive, preventing an unverified feed label from becoming a broad
false-positive rule.

## Sources

- [PhishTank developer feed](https://phishtank.org/developer_info.php) is the
  supported automated source. Its verified feed includes a `target` field for
  the impersonated company or brand and is refreshed hourly. Automated access
  requires a PhishTank application key.
- [Check Point Q2 2026 Brand Phishing Report](https://blog.checkpoint.com/research/which-brands-are-impersonated-most-inside-the-q2-2026-brand-phishing-report/)
  and related public trend reports inform built-in priorities and regression
  scenarios. SentinelMail does not copy a proprietary vendor feed.
- OpenPhish publishes useful brand statistics, but its public terms restrict
  commercial reuse without written permission. SentinelMail therefore does not
  import or redistribute OpenPhish's monthly brand list.

Each stored evidence row retains its own source and licensing note so operators
can audit where an observation came from.

## Enabling PhishTank refreshes

1. Obtain a PhishTank application key.
2. Open **Configuration → System settings → Threat feeds**.
3. Set the API key on `phishtank_brands`.
4. Enable the feed and keep the one-hour refresh interval unless PhishTank
   instructs otherwise.
5. Review **Configuration → Brand intelligence** for source health, last
   refresh, observed-brand count, aliases, and validated official domains.

Super admins can also start an immediate refresh from that page. Refreshes run
in the background and the page reports whether one is active. A super admin can
promote an observed brand only after validating at least one official domain,
edit aliases/domains/context cues, change its priority, or deactivate it. Each
manual change is written to the audit log. MSP admins can search and inspect the
catalog and history but cannot change global protection rules.

The key is never returned by the API. Download failures are deliberately
sanitized because HTTP client errors can otherwise include a key-bearing URL.

## SMTP behavior

Brand-feed refreshes run asynchronously. Inbound SMTP processing only reads the
local cached catalog; it never waits for PhishTank or another external service.
If PostgreSQL catalog loading fails, SentinelMail falls back to the original
small built-in detector so a feed/database issue does not interrupt mail flow.

Passing SPF, DKIM, or DMARC proves control of the sending domain. It does not
prove that an unrelated domain is allowed to claim Spotify, Microsoft, a bank,
or another protected brand. The detector compares claims with validated
official domains before deciding whether to quarantine.

Account-loss and failed-payment lures are handled deterministically when they
combine a protected-brand claim, urgent account or payment language, an update
call to action, and a mismatched sender or actionable-link domain. Static image,
tracking, and unsubscribe URLs are not treated as meaningful brand destinations.
