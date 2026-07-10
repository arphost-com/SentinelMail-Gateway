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

## Open

- [ ] Review vendor-unfixed Trivy OS package findings after the next Debian/Ubuntu/Alpine security refresh and fresh CI scanner artifacts are available.
- [ ] Add screenshots to `docs/role-guides.md` and the in-app Docs page after a populated UI environment is available for stable Users/Dashboard captures.
