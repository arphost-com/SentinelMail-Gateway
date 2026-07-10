# Production install

End state after this guide: a public gateway at `https://your-host.example.com/` accepting SMTP on port 25, scanning + forwarding mail to your downstream MX, with the UI behind Let's Encrypt TLS.

This same install model works for customer onsite deployments and direct internet-facing hosted deployments. In an onsite deployment, the customer owns the server and points their MX records to it. In a hosted/MSP deployment, the provider owns the gateway and creates one SentinelMail organization per customer.

SentinelMail Gateway must run on a VPS, dedicated server, or equivalent host where you control Docker, firewall rules, public ports 25/80/443, persistent volumes, and the server's mail identity. It is not a shared-hosting application. That requirement is intentional and security-relevant: the gateway is an internet-facing MTA, needs to bind privileged SMTP ports, persist Postfix/Rspamd/Postgres state, enforce tenant isolation in its own services, and terminate TLS for the admin UI. Shared hosting normally hides or multiplexes those controls, which would make mail routing, queue ownership, TLS, and audit boundaries ambiguous.

CI security scans run on docker02 before deploy. Trivy is configured to fail on HIGH/CRITICAL repo or image findings when a fixed package exists, and to keep vendor-unfixed OS package findings in the JSON artifacts instead of blocking deploy. This keeps the gate actionable: the images run package upgrades during build, and distro maintainers remain the secure source for libc, Postfix, Rspamd, browser-runtime, and other OS package fixes.

If you've never deployed this before, follow **First Time Setup** below in order — do not skip steps. The optional CI-based deploy is at the bottom.

---

## First Time Setup — step by step

This walkthrough assumes a clean Debian 12 / Ubuntu 24 host with sudo access. No previous Docker experience required. Run each step in order; do not skip ahead.

### Step 1 — pick a hostname and point DNS at the host

You need **one** public DNS name that resolves to the host's public IP. Examples: `mx.example.com`, `spam01.example.com`, `gateway.example.com`. We'll call this `<YOUR-HOSTNAME>` for the rest of this guide.

1. In your DNS provider, create an `A` record:
   - **Name:** the hostname you picked (e.g. `mx`)
   - **Type:** `A`
   - **Value:** the host's public IPv4 address
2. Verify from your laptop:
   ```bash
   host mx.example.com
   # Expected output: mx.example.com has address 1.2.3.4
   ```
3. Do **not** create an `AAAA` (IPv6) record unless inbound IPv6 actually works to your host. Let's Encrypt prefers IPv6 if it sees one and will fail if it can't reach you over v6.

### Step 2 — open firewall ports

Inbound to the host's public IP, from the internet:

| Port | Required | Purpose |
| ---- | -------- | ------- |
| 25   | yes      | Receive SMTP mail from sending MTAs |
| 80   | yes (for TLS) | Let's Encrypt ACME http-01 challenge + redirect to HTTPS |
| 443  | yes      | Web UI over HTTPS |
| 587  | optional | Only if your own clients submit outbound mail through the gateway |

Outbound from the host:
- Port 25 outbound to the internet — required so the gateway can deliver scanned mail to downstream MX servers. Many ISPs / cloud providers block this by default. Test it later in Step 11.

If the host sits behind a NAT/firewall instead of being directly on the internet, see [Scenario B](#scenario-b--behind-a-corporate-firewall) further down before you continue.

### Step 3 — SSH to the host and install Docker

Connect:
```bash
ssh debian@<YOUR-HOSTNAME>
```

Install Docker + git on the host:
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git
```

Add your login user to the `docker` group so you don't need sudo for every command:
```bash
sudo usermod -aG docker $(whoami)
```

**Log out and back in** for the group change to take effect (`exit`, then `ssh ...` again). Verify:
```bash
docker ps
# Expected: empty table with the header CONTAINER ID  IMAGE  COMMAND ...
# If you get "permission denied on /var/run/docker.sock" — you didn't log out and back in.
```

### Step 4 — clone the repository

Pick where you want it; the rest of this guide uses your home directory:

```bash
cd ~
git clone https://10.10.10.96:8929/saas/sentinelmail-gateway.git
cd sentinelmail-gateway
```

(Replace the URL with whatever git mirror is reachable from the host. If your host can't reach any git server, build a tarball on your laptop with `git archive --format=tar.gz -o smg.tgz HEAD` and `scp` it over.)

### Step 5 — create the .env file

The compose stack reads its configuration from `deploy/docker/.env`. Generate it with random secrets:

```bash
./scripts/bootstrap-env.sh
```

The script refuses to overwrite an existing env file. Now edit `.env`:
```bash
nano deploy/docker/.env
```

You **must** set these eight fields. Leave the others at their defaults for now (you can tighten them in [configure.md](configure.md) later).

| Field | What to put | How to generate |
| ----- | ----------- | --------------- |
| `POSTGRES_PASSWORD` | a long random string | `openssl rand -hex 24` (run on your laptop or any machine that has openssl) |
| `API_SESSION_SECRET` | a long random hex string | `openssl rand -hex 32` |
| `API_AUDIT_HMAC_KEY` | a long random hex string | `openssl rand -hex 32` |
| `SMG_INGEST_HMAC_KEY` | a long random hex string | `openssl rand -hex 32` |
| `RSPAMD_PASSWORD` | a long random string | `openssl rand -hex 16` |
| `RSPAMD_CONTROLLER_PASSWORD` | a long random string | `openssl rand -hex 16` |
| `POSTFIX_MYHOSTNAME` | `<YOUR-HOSTNAME>` from Step 1 | (paste the hostname) |
| `SMG_ENV` | `prod` | (literal value) |

For TLS, set these three:
```
TLS_MODE=lets_encrypt
TLS_HOSTNAME=<YOUR-HOSTNAME>
TLS_ACME_EMAIL=you@example.com
```

For the admin account, set these two — they become your first login credentials:
```
SMG_SEED_ADMIN_EMAIL=you@example.com
SMG_SEED_ADMIN_PASSWORD=AStrongPasswordOfAtLeast12Characters
```

(If you skip those two, the system will generate a random admin password on first start and print it to the container logs. Setting them in `.env` is easier.)

Save and exit (`Ctrl-O`, `Enter`, `Ctrl-X` in nano).

### Step 6 — bring the stack up

From `~/sentinelmail-gateway/deploy/docker`:

```bash
docker compose up -d --build
```

This will:
- Pull base images (postgres, redis, clamav, caddy, etc.)
- Build the api, web, postfix, rspamd, worker, sandbox, and caddy images locally from the repo
- Start everything

The first build takes 5–15 minutes depending on the host. Subsequent runs are seconds.

When the prompt returns, check that all 10 services are healthy:
```bash
docker compose ps
```

Expected: every row says `Up X seconds (healthy)`. If anything says `unhealthy` or `restarting`, wait 60 seconds and check again — clamav loads its signature database on first start and takes ~2 minutes to become healthy.

### Step 7 — verify the database was set up automatically

The api container auto-runs migrations and seeds the admin user on startup. You should not need to run anything manually. To confirm:

```bash
docker compose logs api | grep -E "bootstrap|admin"
```

Expected output, one of:
- `bootstrap: admin user created: you@example.com` — first start, seeded with your `.env` credentials.
- `bootstrap: generated admin password: <hex>` — first start, `SMG_SEED_ADMIN_PASSWORD` was empty so a random one was generated. **Copy that password somewhere safe.**
- No bootstrap lines at all — stack was already initialized previously; nothing was changed.

### Step 8 — sign in to the web UI

Open in your browser:

```
https://<YOUR-HOSTNAME>/
```

Caddy will obtain a Let's Encrypt certificate the first time you hit it. This takes ~10 seconds. If you see `ERR_SSL_PROTOCOL_ERROR` immediately on first load, that's the cert still being issued — wait 30 seconds and refresh. If it still fails after 2 minutes, see [troubleshoot.md → TLS / Let's Encrypt](troubleshoot.md).

Sign in with the credentials from Step 5:
- **Email:** the value of `SMG_SEED_ADMIN_EMAIL`
- **Password:** the value of `SMG_SEED_ADMIN_PASSWORD` (or the random one from Step 7's log)

### Step 9 — turn on two-factor authentication

Don't skip this — your account has super-admin power over everything.

1. **Settings → Account**
2. Click **Enable two-factor**
3. Scan the QR code with any TOTP app (Google Authenticator, Authy, 1Password, Bitwarden)
4. Enter the 6-digit code to confirm
5. You'll be prompted for a code on every future login

### Step 10 — register your first domain

The gateway only accepts inbound mail for domains it's been told about. Mail for any other domain is rejected with "unknown recipient domain".

1. **Sidebar → Domains → + New domain**
2. **Name:** the domain you want to receive mail for, e.g. `example.com`
3. Click **Save**

In DNS for that domain, point the MX record at this gateway:
```
example.com.    MX   10   <YOUR-HOSTNAME>.
```

### Step 11 — point the gateway at your downstream mail server

The gateway scans mail, then forwards clean messages to your real mail server (Mailcow, Exchange, Google Workspace, M365, etc.).

1. **Sidebar → Gateways → + New gateway**
2. **Domain:** pick the domain you registered in Step 10
3. **Host:** the hostname or IP of your downstream mail server, e.g. `mail.example.com` or `10.0.0.50`
4. **Port:** `25` (use `587` if your downstream requires submission)
5. **Priority:** `10`
6. Click **Save**

Verify the host can reach your downstream on port 25:
```bash
nc -vz mail.example.com 25
# Expected: Connection to mail.example.com 25 port [tcp/smtp] succeeded!
```

If this fails — **especially the "outbound port 25" check** — your ISP or cloud provider is blocking port 25 outbound. You'll need to configure an outbound smarthost in **System Settings → mail.outbound_relay_host**.

### Step 12 — send a test message

From any machine that can talk to your host on port 25:

```bash
# Install swaks if you don't have it
sudo apt-get install -y swaks

swaks --to test@example.com \
      --from sender@gmail.com \
      --server <YOUR-HOSTNAME> \
      --header "Subject: Smoke test" \
      --body "hello world"
```

Expected output ends with `250 2.0.0 Ok: queued as ...`.

In the UI: **Sidebar → Mail logs** — you should see the message appear within a few seconds, with disposition `delivered` (or `quarantined` if rspamd flagged it). If it appears with disposition `rejected: unknown recipient domain`, you skipped Step 10.

### Step 13 — turn on AI scoring (optional)

Without an Anthropic API key, the AI scan handler falls back to a keyword heuristic — works, but much less accurate. To turn on real Claude scoring:

1. Get an API key at https://console.anthropic.com/
2. Edit `.env`:
   ```bash
   nano ~/sentinelmail-gateway/deploy/docker/.env
   ```
3. Set:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   ```
4. Restart the worker:
   ```bash
   cd ~/sentinelmail-gateway/deploy/docker
   docker compose up -d worker
   ```

### Step 14 — back up your .env file

Lose `.env` and you lose access to the database (the `POSTGRES_PASSWORD` is the only way back in to your data). Copy it somewhere safe:

```bash
# From your laptop:
scp debian@<YOUR-HOSTNAME>:~/sentinelmail-gateway/deploy/docker/.env ./sentinelmail-env.backup
chmod 600 ./sentinelmail-env.backup
```

Store that file in a password manager or encrypted backup. **Without it, this install is unrecoverable if the host dies.**

You're done. Skip to the bottom of this page if you want to set up CI/CD; otherwise see [configure.md](configure.md) for tuning and [use.md](use.md) for day-to-day operation.

---

## What you need (reference)

- Debian 12 / Ubuntu 24 host, **2 CPU, 4 GB RAM, 30 GB disk** minimum (the sandbox worker image is ~1.2 GB, so 6 GB disk free if you're tight)
- Sudo access on the host
- A public DNS hostname pointing at the host
- The firewall ports from Step 2 reachable
- Outbound port 25 (test in Step 11)

---

## Scenario B — behind a corporate firewall

If the host has a private IP and a firewall does NAT to the internet:

### B1 — full inbound MX (you want to receive internet mail)

Configure port forwarding on the firewall to the host's private IP:

| Public | Internal | Why |
| ------ | -------- | --- |
| 25 → 25   | host:25  | Inbound SMTP |
| 80 → 80   | host:80  | Let's Encrypt ACME http-01 challenge |
| 443 → 443 | host:443 | UI access |
| 587 → 587 | host:587 | Only if external clients submit through the gateway |

DNS for the gateway hostname points at the **firewall's** public IP, not the host's private one. Otherwise follow First Time Setup unchanged.

**Common gotchas:**
- **Outbound port 25 blocked.** Most ISPs and corporate egress filters block it. Run `nc -vz aspmx.l.google.com 25` from the host. If blocked, you need a smarthost (see `mail.outbound_relay_host` in System Settings).
- **TLS inspection / SNI rewriting** on the firewall will break the UI for users — they'll see your firewall's cert, not yours. Exempt this hostname from inspection.

### B2 — internal-only gateway (no public mail)

Don't open any public ports. In `.env`:
```
TLS_MODE=self_signed
TLS_HOSTNAME=<internal-hostname>
```

Bind the UI to the host's LAN IP and have your internal MX deliver to the gateway over the LAN.

---

## Optional — CI/CD push-to-deploy

If your host can reach the GitLab runner network, you can wire up automatic deploys instead of pulling + rebuilding by hand.

### Register a GitLab shell runner on the host

```bash
sudo apt-get install -y gitlab-runner
sudo gitlab-runner register \
  --url http://10.10.10.96:8929 \
  --token "glrt-...your-runner-token..." \
  --executor shell \
  --description "spam01" \
  --tag-list "spam01" \
  --user debian
```

Get the runner token from **GitLab → project → Settings → CI/CD → Runners → New project runner**, tag it `spam01` (or whatever you named the host).

### Grant the runner sudo for the deploy step

```bash
sudo visudo -f /etc/sudoers.d/gitlab-runner-sentinelmail
```

Add:
```
debian ALL=(root) NOPASSWD: /usr/bin/install
```

(Substitute `debian` with whatever user you registered the runner as.)

### Trigger the deploy

**GitLab → project → CI/CD → Pipelines → latest commit → ▶ on `deploy:spam01`.**

The job runs on the shell runner, rsyncs source into `/home/<runner-user>/docker/sentinelmail-gateway/`, generates `.env` with random secrets if missing (never overwrites an existing one), rebuilds, restarts. The seeded admin password is in the job log — save it.

### Publish the public GitHub mirror

GitLab remains the canonical deploy repo. GitHub is the public GPLv3 mirror and the place outside users can report bugs or send pull requests.

Configure a masked/protected GitLab CI/CD variable named `GITHUB_PAT` with GitHub Contents read/write access for `arphost-com/SentinelMail-Gateway`. Then run:

**GitLab -> project -> CI/CD -> Pipelines -> latest `main` pipeline -> `push:github`.**

The job pushes the checked GitLab commit to `https://github.com/arphost-com/SentinelMail-Gateway` as `main` and verifies GitHub's `main` SHA matches the GitLab commit. It is manual by design, so public releases happen only when an operator chooses to publish them.

---

## What the stack actually does on `docker compose up -d --build`

For reference — there is no magic, just standard Docker behavior:

1. Builds 7 images from the repo: api, web, postfix, rspamd, worker, sandbox, caddy
2. Pulls 3 base images: postgres, redis, clamav
3. Starts the 10 containers in dependency order (postgres + redis + clamav first, then rspamd, then everything else)
4. The api container auto-runs `bootstrap.MigrateAndSeed` on startup:
   - Applies any pending goose migrations to postgres
   - Creates the System organization + super_admin user if the orgs table is empty
   - Honors `SMG_SEED_ADMIN_EMAIL` / `SMG_SEED_ADMIN_PASSWORD` if set, otherwise generates a random password and logs it
5. Caddy issues a Let's Encrypt certificate on first HTTPS request (if `TLS_MODE=lets_encrypt`)

Re-running `docker compose up -d --build` after a `git pull` rebuilds + restarts — preserves the postgres, redis, rspamd, clamav, postfix-spool, and caddy data volumes. Migrations re-apply (idempotent). Seed no-ops because the org already exists.

To bypass the auto-migrate (e.g. you want to run migrations from a separate tool):
```
SMG_AUTO_MIGRATE=false
```
in `.env`. You'll then need to run `docker compose exec -T api /app/migrate up` yourself before the api will accept requests.

---

## See also

- [configure.md](configure.md) — TLS, DNS, ports, AI key, threat feeds
- [troubleshoot.md](troubleshoot.md) — common failures and how to fix them
- Main [README.md](../README.md) — architecture + REST API reference
