# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
      postfix postfix-pcre postfix-pgsql rsyslog ca-certificates tini python3 \
    && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
    && rm -rf /var/lib/apt/lists/*

COPY main.cf  /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY pgsql-relay-domains.cf.template /etc/postfix/pgsql-relay-domains.cf.template
COPY pgsql-transport.cf.template     /etc/postfix/pgsql-transport.cf.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY smtp-event-forwarder.py /usr/local/bin/smtp-event-forwarder.py
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/smtp-event-forwarder.py

EXPOSE 25 587
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD postfix status >/dev/null 2>&1 || exit 1

# Postfix's master process must run as root to bind privileged ports 25/587
# and to manage queue directories owned by the `postfix` / `postdrop` users.
# It performs privilege separation internally: worker daemons (smtpd, cleanup,
# qmgr, smtp, etc.) re-exec under the unprivileged `postfix` user defined by
# the package, so the running container is *not* a single root process even
# though the entrypoint is. Replacing this with `USER postfix` breaks port
# binding and queue management — there is no safe alternative for an MTA.
# Documented suppression for repo-wide scanners (both trivy and semgrep have
# their own marker conventions):
# trivy:ignore:DS002
# trivy:ignore:DS-0002
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
