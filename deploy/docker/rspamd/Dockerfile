# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg lsb-release tini \
    && curl -fsSL https://rspamd.com/apt-stable/gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/rspamd.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/rspamd.gpg] http://rspamd.com/apt-stable/ $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/rspamd.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends rspamd \
    && rm -rf /var/lib/apt/lists/*

# Drop in config overlays.
#   local.d/        — UCL section overlays + worker-*.inc files
#   lua.local.d/    — user Lua plugin files (just storage; not auto-loaded)
#   rspamd.conf.local — top-level overlay file that rspamd .includes by
#                       default; this is where the `lua = ...` directive
#                       that activates smg_ingest.lua lives, since local.d/
#                       files only merge into sections matching the filename
#                       (no built-in section is named "smg_lua_loader").
COPY conf/local.d/         /etc/rspamd/local.d/
COPY conf/lua.local.d/     /etc/rspamd/lua.local.d/
COPY conf/rspamd.conf.local /etc/rspamd/rspamd.conf.local
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh && \
    mkdir -p /var/lib/rspamd && chown -R _rspamd:_rspamd /var/lib/rspamd /etc/rspamd

USER _rspamd
EXPOSE 11332 11333 11334
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=10 \
    CMD rspamadm control stat >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
