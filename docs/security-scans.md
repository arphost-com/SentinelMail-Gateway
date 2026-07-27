# Security Scan Review

This page records the current scanner review status for SentinelMail Gateway.

## Current Trivy Review

- Reviewed on: 2026-07-04
- GitLab pipeline: `main` pipeline `1623` for commit `d535825`
- Pipeline status: success
- Trivy repo job: `security:trivy-repo` job `17143`
- Trivy container job: `security:trivy-containers` job `17144`

The downloaded JSON artifacts reported zero HIGH or CRITICAL findings for:

| Target | HIGH/CRITICAL findings |
| --- | ---: |
| Repository/config scan | 0 |
| `api` image | 0 |
| `web` image | 0 |
| `caddy` image | 0 |
| `postfix` image | 0 |
| `rspamd` image | 0 |
| `worker` image | 0 |
| `sandbox` image | 0 |

No vendor-fixed OS package findings were present in the current Trivy artifacts, so no Dockerfile or base-image update is needed from this review.

## Policy

GitLab runs Trivy with `--ignore-unfixed` for repository and container scans. The security gate fails on HIGH or CRITICAL findings when Trivy reports an available fix. Vendor-unfixed distro package issues stay out of the gate artifacts until Debian, Ubuntu, Alpine, or upstream runtime security refreshes publish fixes.

When reviewing a future Trivy refresh:

1. Open the latest successful `main` pipeline.
2. Download the artifacts from `security:trivy-repo` and `security:trivy-containers`.
3. Confirm the JSON reports have no HIGH or CRITICAL vulnerabilities with a non-empty `FixedVersion`.
4. If fixed versions are available, refresh the affected base image or package installation path and rerun CI.
5. If no fixed versions are available, keep the finding in the artifact review notes and do not fork distro packages locally.
