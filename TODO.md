# SentinelMail TODO

## Completed

- [x] Add docker02 security scanners to the GitLab pipeline and publish scanner artifacts.
- [x] Add deploy-time `.env` bootstrap for `deploy/docker/.env` without overwriting existing secrets.
- [x] Move sidebar sign-out below the visible menu items so it moves down as navigation grows.
- [x] Check production SentinelMail logs on `spam01` for current delivery/stat issues.
- [x] Make dashboard mail-history graph clickable and show the selected bucket's exact email count.
- [x] Make reports metrics and supported report graphs clickable so they drill into matching mail logs.
- [x] Patch Dockerfile package refreshes after Trivy container scan found stale OS/runtime packages.
- [x] Document Trivy's vendor-unfixed package policy for docker02 security scans.
- [x] Treat `medicalsitesolutions.com` and `yawausa.com` queue deferrals as spam/backscatter noise, not contacts requiring delivery repair.
- [x] Add SMTP event visibility for Postfix-only rejects, TLS failures, and downstream deferrals before `/api/v1/mail/events`.
- [x] Keep SMTP `NOQUEUE` rejects separate from accepted mail logs by recording them in SMTP Events.
- [x] Fix Caddy ACME storage so certificates and accounts live in the persisted `/data/caddy` volume.
- [x] Review SMTP Events after production collected Postfix rejects/deferrals; confirmed local sender-list rejects and identified spam/backscatter queue noise.
- [x] Make Quarantine table match the Users-page density: date/from/to/subject/score/action columns stay one line, with overflow moved to Details.
- [x] Add Quarantine Details tabs for summary, content, headers, and raw metadata from the stored quarantine blob where available.
- [x] Clarify the Threats page copy so admins understand it shows async scan jobs/results, not the quarantine list or sender blocklists.
- [x] Promote scanner-verified phishing/malware into Quarantine and keep large scan screenshots out of the Threats list response.
- [x] Force SMTP rejection after SentinelMail records a quarantined message so held mail is not relayed downstream.
- [x] Add user-facing phishing alert emails with sender address, subject, source IP, detection reason, quarantine link, and user-selectable off/immediate/daily/weekly cadence defaulting to weekly.
- [x] Add an authenticated source-IP abuse report action on quarantine details with RDAP abuse-contact lookup, safe metadata-only report preview, and outbound-relay sending.
- [x] Set `barry@qreg.net` to immediate phishing alerts after deploying the preference migration.
- [x] Add a dedicated Rspamd/Postfix operations skill covering SPF, DKIM, DMARC, RBL/URI blocklists, quarantine semantics, Postfix milters, deployment, rollback, and production smoke checks.
- [x] Align inbound authentication decisions with SPF/DKIM/DMARC best practices: accept DMARC pass, do not require SPF+DKIM+DMARC all to pass, quarantine DMARC reject/quarantine policy failures, and quarantine fully unauthenticated mail for review.
- [x] Treat DNSBL/URIBL lookup failures and rate-limit symbols such as `URIBL_BLOCKED` as scanner health signals, not reputation blocklist hits.
- [x] Make suspected spam/blocklist/auth failures quarantine-first instead of SMTP hard rejects so false positives can be reviewed and released without sender backscatter.
- [x] Add regression tests for legitimate authenticated senders, lookup-blocked RBL symbols, sender blocks, and quarantine SMTP behavior before the next production rollout.
- [x] Add admin UI for org/domain/user sender allowlists and blocklists so staff do not need SQL for whitelist/blacklist entries.
- [x] Keep obvious phishing quarantined by deterministic checks first while leaving AI analysis as an optional deeper review layer, not the required path for catching known lures.
- [x] Make dashboard and report drilldowns carry exact mail-log filters, including window bounds and chart bucket filters.
- [x] Let users choose how background-task completions notify them: email, in-app status, both, or off. Wire the preference through account settings, backend user settings, queued bulk quarantine jobs, and queued-action UI copy.
- [x] Review and demote/remove existing scanner phishing reports created by the old sandbox tracking-link heuristic if they are not true phishing.
- [x] Suppress deferred queue noise for known spam/backscatter domains by hiding deferred/bounced/failed SMTP events tied to blocklisted senders by default, with an operator toggle to show them.
- [x] Add a downloadable customer-facing quick-start PDF for onsite installs and MSP-hosted customer onboarding.
- [x] Review fresh Trivy artifacts after the Debian/Ubuntu/Alpine security refresh; latest `main` pipeline `1623` reported zero HIGH/CRITICAL repo or image findings.
- [x] Replace the screenshot TODO with a sanitized screenshot capture guide and wire screen-reference guidance into `docs/role-guides.md` and the in-app Docs page.
- [x] Fix the desktop quarantine abuse-report flow so its preview replaces the message dialog instead of opening a second stacked native dialog.
- [x] Give every modal a unique accessible title relationship and repair form labels that contained interactive help controls.
- [x] Replace misleading "No spoof signal detected" text with explicit authenticated, unavailable, or suspicious sender-authentication states.
- [x] Show the stored Rspamd score contributions and the original-message attachment status before an abuse report can be sent.
- [x] Clarify held/released quarantine wording and hide release timestamps when a message has never been released.
- [x] Only show mailbox release/delete-held actions when an original held quarantine copy actually exists.
- [x] Correct dashboard/report outcome totals so blocked messages are not counted again as rejected or failed.
- [x] Tighten threat-category rules so unavailable/rate-limited DNSBL checks and broad DMARC/virus symbol names do not create false phishing, malware, or reputation totals.
- [x] Count unique reported messages in the phishing-report headline instead of summing duplicate report events.
- [x] Keep report dates on their UTC report day and distinguish chart loading states from genuinely empty results.
- [x] Add a compact mobile navigation menu, remove duplicate page headings, improve theme contrast, and fix danger-button foreground colors across all supported themes.
- [x] Surface sender-list API errors, rename the ambiguous add-domain action, update stale in-app navigation instructions, and correct the production environment URL in GitLab.
- [x] Add regression coverage for sender-authentication labels, report dates, authentication analysis, and threat-category false-positive guards.

## Open

### P0 — Stop repeated mail-classification failures

- [x] Preserve the original inline quarantine reason when an asynchronous scanner adds evidence; alerts and Mail Logs now retain the original policy trigger and append the scanner verdict instead of replacing the useful reason with `scanner detected suspicious phishing indicators`.
- [ ] Pass authenticated sender-domain context into browser-sandbox jobs. A normal `account`, `login`, `review`, or `secure` path on the authenticated sender's registrable domain must not become phishing solely because of those path words; cross-domain forms, credential collection on unrelated domains, and threat-feed hits must remain blocking signals.
- [x] Add a legitimate transactional-mail regression fixture for `outbound.figure.com` / `Figure Loan Statement`, including its SparkPost-style VERP sender, SPF/DKIM/DMARC alignment, and the first-party `figure.com` `RSPAMD_URIBL` hit; first-party URL reputation no longer becomes hard quarantine, while unrelated and unauthenticated URL hits remain blocked.
- [ ] Add a confirmed-spam regression fixture based on the `info.prolivingtip.com` campaign reported from `Eric@info.prolivingtip.com`; derive generic solicitation/campaign signals from the full stored message and require quarantine without hardcoding a one-off sender rule.
- [ ] Make mailbox `Spam` feedback immediately create recipient-scoped sender/domain learning, then verify the next matching campaign copy is quarantined before SMTP delivery. Keep `Not spam` feedback scoped and require authenticated alignment before it can override reputation or content signals.
- [ ] Audit the last 30 days of production false positives and false negatives by disposition, user verdict, sender domain, authentication state, Rspamd symbols, scanner kind/evidence, terminal Postfix action, and release state. Convert every confirmed incident into a sanitized regression fixture.
- [ ] Add an end-to-end mail-flow acceptance suite that injects legitimate transactional mail, newsletters, obvious spam, homoglyph phishing, reputation-listed mail, and user-learned senders through Postfix/Rspamd/API. Assert both the database disposition and terminal Postfix delivery/discard action.
- [ ] Add production rollout gates: zero quarantined-to-delivered mismatches, all incident fixtures passing, Rspamd configuration validation, API/worker health checks, and a canary mailbox verification on `docker02` before the manual `spam01` deployment.
- [ ] After deployment, monitor and report false-positive rate, false-negative user reports, quarantine release rate, scanner reason distribution, and delivery mismatches daily for seven days; treat any recurrence of these fixtures as a rollback/blocking failure.
- [ ] Resolve and independently verify the changed `spam01` SSH host key before any direct production operation; do not bypass host-key checking.

- [x] Add Spotify to protected-brand impersonation detection and add a sanitized regression fixture for the `worldlibertyfinancial.com.co` payment-update lure. Treat SPF/DKIM/DMARC success for an unrelated sender-owned domain as authenticated transport, not proof that the claimed brand is legitimate.
- [x] Build a sourced phishing-brand intelligence database covering approximately 100–1,000 commonly impersonated brands. Research current public phishing feeds and industry reports, rank observed targets, normalize brand names/aliases and official domains, retain source/licensing/last-seen metadata, support safe scheduled refreshes, and make inbound brand-impersonation detection use the database instead of relying only on the small hardcoded brand list.
- [x] Finish administration controls for the phishing-brand database: super admins can manually refresh, promote observed brands, edit aliases/domains/cues and protection state, and review audit history. MSP admins retain read-only catalog visibility.
- [x] Add regression and false-positive coverage for authenticated third-party senders, legitimate marketing platforms, regional brand domains, lookalike domains, and attacker-controlled domains that pass SPF/DKIM/DMARC.
- [x] Expand deterministic account/payment-update detection for known-brand claims combined with failed-payment or account-loss pressure, update-details calls to action, and sender/link domain mismatch.
- [x] Prioritize up to three distinct actionable CTA destinations for sandboxing while excluding images, tracking pixels, static assets, unsafe schemes, and unsubscribe links.
- [x] Return explicit `unavailable` and `inconclusive` async-analysis verdicts and surface the latest AI availability in system health without treating heuristic metadata as a clean AI result.
- [x] Disable unsubscribe links and one-click unsubscribe actions after a message is marked phishing or malware, with an attacker-link safety warning.
- [x] When a user reports phishing or malware, correlate matching unreviewed mailbox copies in the same recipient campaign so duplicates are no longer presented as ordinary mailing-list mail.
- [x] Add daily normalized campaign fingerprints using sender/domain, recipient, subject, and stable content hash, with first/last seen, copy count, and unique source-IP count.
- [x] Add quarantine flood suppression that retains one representative raw message and aggregates subsequent high-confidence copies without duplicating held blobs or scan jobs.
- [x] Add tenant policy controls for the campaign threshold and aggregate, SMTP-reject, or accept-and-discard handling without generating backscatter.
- [x] Make phishing alerts and abuse reports campaign-aware: one representative alert is sent, and reports include campaign counts and source networks.
- [x] Add a Trust Card regression/load test proving that 1,718 messages from 1,101 source IPs collapse to one stable campaign while remaining blocked.
- [x] Deploy the completed sender-auth wording, abuse-preview, campaign aggregation, and detection changes to `spam01` through its authenticated production runner; verify migrations and production smoke checks.
- [x] Reconcile quarantine persistence with the final SMTP outcome: store bounded queue-ID correlations for Postfix delivery/discard/reject/bounce/failure actions, flag quarantined or rejected messages that are subsequently relayed, expose terminal evidence in Mail Logs and production diagnostics, and document that historical inbox copies require their full `Received` headers when they predate outcome tracking.
