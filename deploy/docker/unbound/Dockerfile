# syntax=docker/dockerfile:1.7
FROM alpine:3.24

RUN apk upgrade --no-cache && \
    apk add --no-cache drill unbound && \
    install -d -o unbound -g unbound -m 0750 /var/lib/unbound && \
    cp /usr/share/dnssec-root/trusted-key.key /var/lib/unbound/root.key && \
    chown unbound:unbound /var/lib/unbound/root.key

COPY --chown=unbound:unbound unbound.conf /etc/unbound/unbound.conf
RUN unbound-checkconf /etc/unbound/unbound.conf

USER unbound
EXPOSE 5353/tcp 5353/udp

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD drill -p 5353 @127.0.0.1 localhost. A | grep -q 'IN.*A.*127.0.0.1' || exit 1

ENTRYPOINT ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
