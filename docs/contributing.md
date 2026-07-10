# Contributing and Updates

SentinelMail Gateway is GPLv3-or-later open source. GitLab is the canonical working repo for ARPHost CI, security scans, deployments, and releases. GitHub is the public mirror where outside users can report bugs, request features, and send fixes.

## Public Repository

- GitHub: `https://github.com/arphost-com/SentinelMail-Gateway`
- License: GNU General Public License v3.0 or later
- Root contribution guide: [`../CONTRIBUTING.md`](../CONTRIBUTING.md)

## Bug Reports from Users

Ask users to file GitHub issues with:

- Commit SHA or release tag
- Deployment type and host layout
- Sanitized logs from the affected service
- Steps to reproduce
- Expected result and actual result
- Whether mail flow is blocked, degraded, or unaffected

Never ask users to paste secrets, full `.env` files, session cookies, private message bodies, unsanitized customer addresses, or raw quarantined messages into public issues.

## Applying External Updates

When someone reports a bug or sends a GitHub pull request:

1. Reproduce or review the report.
2. Apply the accepted fix to the canonical GitLab repo.
3. Update tests and documentation with the code change.
4. Let GitLab CI run the check and security stages.
5. Confirm docker02 deploy and smoke pass.
6. Trigger the manual `push:github` GitLab job to publish the update back to GitHub.

This keeps the public repo current without bypassing the GitLab checks that protect the production deployment workflow.

## Manual GitHub Publish Job

The GitLab pipeline includes `push:github`, a manual `main`-branch job. It requires a masked/protected `GITHUB_PAT` CI/CD variable with GitHub Contents read/write access for `arphost-com/SentinelMail-Gateway`.

Run it from **GitLab -> CI/CD -> Pipelines -> latest main pipeline -> `push:github`**. The job publishes a filtered public tree to GitHub, excluding `.gitlab-ci.yml` and `.gitlab/`, then verifies those CI/CD files are absent from the public commit.
