# Contributing to SentinelMail Gateway

SentinelMail Gateway is released under the GNU General Public License v3.0 or later. The public GitHub repository is open for bug reports, fixes, and operational feedback from people running the gateway.

## Where Work Happens

GitLab is the canonical working repository for ARPHost-maintained CI, security scans, docker02 deployment, and spam01 production deployment.

GitHub is the public mirror and community intake point:

- Repository: `https://github.com/arphost-com/SentinelMail-Gateway`
- Issues: bug reports, install problems, documentation gaps, feature requests
- Pull requests: proposed fixes and documentation updates

Accepted GitHub fixes are applied to the canonical GitLab repository, run through GitLab CI, then published back to GitHub with the manual `push:github` pipeline job.

The GitHub mirror intentionally excludes GitLab CI/CD files. Deployment and security-scan pipeline configuration stays in GitLab.

## Reporting Bugs

Open a GitHub issue and include:

- SentinelMail commit SHA or release tag
- Deployment type: local Docker Compose, customer onsite, MSP/hosted, docker02, or spam01
- Relevant service logs with secrets removed
- Steps to reproduce
- Expected behavior and actual behavior
- Whether mail flow is blocked, degraded, or unaffected

Do not post passwords, API keys, session cookies, `.env` files, private message bodies, customer addresses, or raw quarantined mail unless it has been sanitized.

## Sending Fixes

Open a GitHub pull request against `main`.

Before submitting:

- Keep changes scoped to one bug or feature.
- Preserve tenant isolation for every API, query, and UI list.
- Keep SMTP hot-path work lightweight; browser sandboxing, QR analysis, AI calls, and other slow work belong in async workers.
- Follow the repo security guardrails: no hardcoded secrets, no unsafe redirects, no raw untrusted HTML, no disabled CSRF in production paths, and no request-controlled `href` or `src` output.
- Update docs when behavior, configuration, deployment, or user workflows change.
- Add or update tests for backend behavior, frontend logic, migrations, or mail-processing changes.

Useful local checks:

```bash
go vet ./...
go test ./... -race -count=1
cd web && npm run build
docker compose -f deploy/docker/docker-compose.yml config
```

Run the checks that match your change. If you cannot run one, explain why in the pull request.

## Maintainer Update Flow

For ARPHost maintainers:

1. Triage GitHub issues and pull requests.
2. Apply accepted fixes to the canonical GitLab repository.
3. Run the normal GitLab pipeline on `main`.
4. Confirm `check`, `security`, `deploy:docker02`, and `smoke:docker02` pass.
5. Run the manual `push:github` job to publish `main` to GitHub.

Configure `GITHUB_PAT` in GitLab CI/CD variables as masked and protected. It needs GitHub Contents read/write access for `arphost-com/SentinelMail-Gateway`.

The `push:github` job intentionally does not run automatically. A maintainer must trigger it from the GitLab pipeline, the same way manual production jobs are triggered. The job publishes a filtered public tree and verifies `.gitlab-ci.yml` / `.gitlab/` are absent from the GitHub commit.
