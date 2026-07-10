# Troubleshooting

Real bugs we've hit (and fixed) during MVP rollout. Symptom → diagnosis → fix.

If you find a new bug in a public release, file a GitHub issue at `https://github.com/arphost-com/SentinelMail-Gateway` with the commit SHA, deployment type, sanitized logs, reproduction steps, expected behavior, and actual behavior. Do not include secrets, `.env` files, private message bodies, customer addresses, or raw quarantined mail.

## Login

### POST /auth/login returns 200 but the UI bounces back to the login screen

**Cause:** `SMG_ENV=prod` (or anything except `dev`) marks the session cookie `Secure`. Browsers drop `Secure` cookies on plain HTTP, so the next request has no cookie and the SPA thinks you're not signed in.

**Fix:** either put TLS in front (`TLS_MODE=lets_encrypt` or `self_signed`) **OR** set `SMG_ENV=dev` in `.env` and restart api.

### Login returns mfa_required but my code keeps failing

**Cause:** TOTP code generators include a 30-second window; check your phone's clock is in sync. If you genuinely lost the device, use the `reset-admin` CLI (see below) — it resets the password *and* clears MFA in one shot.

### Lost the admin password / locked out of MFA / want to rename the default admin

Run `reset-admin` against the api container. Generates a fresh password (printed to stdout) and clears MFA enrollment. Optionally renames the account in the same call.

```bash
# Reset password only — prints a new random one
docker compose exec -T api /app/migrate reset-admin admin@sentinelmail.local

# Reset password AND rename
docker compose exec -T api /app/migrate reset-admin admin@sentinelmail.local barry@arphost.com

# Set an explicit password instead of generating one
docker compose exec -T -e SMG_RESET_PASSWORD='YourPass12+' api /app/migrate \
  reset-admin admin@sentinelmail.local
```

Works on any user, not just the default admin. The new password is hashed before it touches the database; nothing readable is persisted.

## Stack

### Pipeline deploy fails at step 1 with `sudo: install: command not found`

**Cause:** the shell runner's user doesn't have sudo for `install`.

**Fix:** add to `/etc/sudoers.d/<runner-user>`:

```
debian ALL=(root) NOPASSWD: /usr/bin/install
```

(Substitute the actual runner username.)

### docker compose up fails with `address already in use`

**Cause:** something already owns the port.

**Common offenders:**

- **Port 25** — Debian's `exim4` binds 127.0.0.1:25 by default. Set `SMG_SMTP_LISTEN_IP=<your external IP>` so postfix binds a different address.
- **Port 80 / 443** — host nginx or another reverse proxy. Set `SMG_CADDY_HTTP_PORT=8090` and `SMG_CADDY_HTTPS_PORT=8443`, front externally.

### Rspamd crash-loops, logs only show `is loading configuration`

**Cause:** Lua snippet has a syntax error or imports a module that doesn't exist (we hit `cjson.safe` once — fixed by switching to rspamd's bundled `ucl`).

**Fix:** validate the config from outside the running container:

```bash
docker run --rm --entrypoint=rspamadm \
  -v /home/debian/sentinelmail-gateway/deploy/docker/rspamd/conf/local.d:/etc/rspamd/local.d:ro \
  -v /home/debian/sentinelmail-gateway/deploy/docker/rspamd/conf/lua.local.d:/etc/rspamd/lua.local.d:ro \
  sentinelmail-rspamd configtest
```

### Postfix crash-loops: `fatal: missing 'postlog' service in master.cf`

**Cause:** postfix 3.4+ requires a `postlog` service in master.cf. The current `deploy/docker/postfix/master.cf` includes it; if you've modified the file and stripped it, add back:

```
postlog   unix-dgram n  -       n       -       1       postlogd
```

### Web container shows "unhealthy" but the UI loads fine

**Cause:** busybox `wget` tries `::1` (IPv6) first when the URL is `localhost`, and nginx in our image binds IPv4 only.

**Fix:** the current healthcheck uses `127.0.0.1` explicitly. If you've edited it back to `localhost`, change it to `127.0.0.1`.

### After redeploy, the UI returns 502 from nginx

**Cause:** nginx upstream cached the api container's old IP at startup; api was recreated with a new IP; nginx never re-resolves.

**Fix:** the current `nginx.conf` uses `resolver 127.0.0.11 valid=10s` + a variable in `proxy_pass` so it re-resolves every request. If you've reverted to the static `upstream` block, restore the resolver pattern.

### `db.Ping()` fails after deploy, then succeeds

**Cause:** postgres is still bootstrapping when api comes up.

**Fix:** the compose `depends_on: postgres: condition: service_healthy` waits for the postgres healthcheck. If you see this with the standard compose, postgres took longer than usual; `docker compose restart api` usually fixes.

## Auto-trigger pipeline (rspamd → /mail/events → scans)

### `/mail/events` returns 401 `bad signature`

**Cause:** `SMG_INGEST_HMAC_KEY` differs between the api container and the rspamd container.

**Fix:** verify both got the same value:

```bash
grep ^SMG_INGEST_HMAC_KEY /home/debian/sentinelmail-gateway/deploy/docker/.env
docker compose exec rspamd printenv SMG_INGEST_HMAC_KEY
docker compose exec api    printenv SMG_INGEST_HMAC_KEY
```

If the rspamd container's value differs, the compose env wiring is wrong — both should pull from the same `.env` line.

### `/mail/events` returns 202 with `unknown recipient domain`

**Working as intended** — the recipient's domain isn't registered in the Domains page. Add it.

### Dashboard always shows zeros

Either no mail has flowed yet, OR your recipient domain isn't registered (see above), OR the Lua snippet isn't loaded. Check rspamd logs for `SMG_INGEST` symbol registration.

## Scans (Threats page)

### Scan stuck in `queued` forever

**Cause:** worker container isn't picking up jobs.

**Fix:** `docker compose logs worker` (for qr/ai/outbound) or `docker compose logs sandbox` (for sandbox). Usually `SMG_INGEST_HMAC_KEY` missing from the worker env.

### AI scan engine says `heuristic-fallback`

`ANTHROPIC_API_KEY` isn't set in the worker env. Add it to `.env` and `docker compose restart worker`. See [configure.md](configure.md#anthropic--claude-ai-scoring).

### Sandbox scan returns `failed: navigation error`

The URL doesn't load — could be a 4xx/5xx, DNS failure, or timeout. Increase `timeout_ms` in the payload if a slow site is the issue; otherwise the URL is probably actually dead (which is sometimes a phishing signal in itself).

## TLS

### Caddy fails to start: `chown: unknown user/group caddy:caddy`

**Cause:** `caddy:alpine` image doesn't include a `caddy` user (only the rootless variant does).

**Fix:** the current `deploy/docker/caddy/Dockerfile` creates `smgcaddy` and uses `setcap` for port binding. If yours doesn't, take a fresh copy.

### Let's Encrypt issuance fails: `acme: error: 403`

**Cause:** the ACME HTTP-01 challenge can't reach port 80 on your host. Most common: corporate firewall blocks 80 inbound, or DNS A record doesn't actually resolve to your host.

**Fix:** verify externally:

```bash
curl http://your-host.example.com/.well-known/acme-challenge/test
```

If that hits Caddy, ACME should work too.

### Let's Encrypt issuance fails: duplicate certificate rate limit

**Cause:** Caddy had to request the same certificate too many times in seven days. The usual cause is lost ACME storage after container rebuilds or volume changes.

**Fix:** current SentinelMail Caddy images force ACME storage to `/data/caddy`, backed by the `caddy_data` named volume. Verify it before rebuilding:

```bash
docker compose exec caddy find /data/caddy/certificates -maxdepth 4 -type f
```

If files only exist under `/home/smgcaddy/.local/share/caddy`, copy them into `/data/caddy` before recreating the container.

### After flipping TLS mode in the UI, nothing changes

**Cause:** the System Settings UI persists TLS values to the database, but the live Caddy reads from `.env`. The UI-to-Caddy autosync is a follow-up.

**Fix:** edit `.env` to match the UI values, then `docker compose restart caddy`.

## Threat feeds

### Threat feed shows `error` in Settings → Threat feeds

Look at `last_refresh_err`. Usually:

- **Spamhaus** — your DNS server rate-limited the queries. Use your own resolver.
- **URLhaus** — outbound HTTPS to abuse.ch is blocked. Open egress.
- **OpenPhish** — needs an API key. Paste it in the per-feed settings.

Mail flow continues regardless — feed errors never block delivery.

## CI / deploy

### Pipeline failed but I can't see why

The runner uploads the full trace to GitLab; check it under **CI/CD → Jobs → click the failed job**. Local-only diagnostic:

```bash
ssh docker02 'sudo journalctl -u gitlab-runner --since "10 min ago" | grep -E "job-status|FAILED"'
```

(The runner's local logs are metadata only — the script output goes to GitLab.)

### deploy:spam01 manual job not appearing

**Cause:** the spam01 shell runner isn't registered with the `spam01` tag, OR the runner is offline.

**Fix:** GitLab → Settings → CI/CD → Runners — check spam01 shows as available with the tag.

## When all else fails

```bash
# State of every container
docker compose -f deploy/docker/docker-compose.yml ps

# Logs for everything for the last 5 minutes
docker compose -f deploy/docker/docker-compose.yml logs --since 5m

# Full bring-down + rebuild + bring-up (preserves data volumes)
docker compose -f deploy/docker/docker-compose.yml down
docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d --build --wait --wait-timeout 180
```

If even that doesn't help, the postgres data is on the `postgres_data` named volume — back it up before nuking:

```bash
docker run --rm -v sentinelmail_postgres_data:/source -v $PWD:/dst alpine \
  tar czf /dst/pg-backup-$(date +%F).tgz -C /source .
```

---

## See also

- [install.md](install.md), [configure.md](configure.md), [use.md](use.md)
- Main [README.md](../README.md#troubleshooting) — quick-table of the same issues
