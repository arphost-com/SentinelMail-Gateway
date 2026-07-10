# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS build
ARG CADDY_VERSION=v2.11.4

RUN apk add --no-cache git
WORKDIR /src/caddy
RUN git clone --depth 1 --branch "${CADDY_VERSION}" https://github.com/caddyserver/caddy.git . && \
    go mod edit -require github.com/go-jose/go-jose/v3@v3.0.5 && \
    go mod tidy && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/caddy ./cmd/caddy

FROM alpine:3.23

ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates libcap && \
    addgroup -g 10005 -S smgcaddy && \
    adduser -u 10005 -S -G smgcaddy smgcaddy && \
    mkdir -p /data /config /etc/caddy && \
    chown -R smgcaddy:smgcaddy /data /config /etc/caddy

COPY --from=build /out/caddy /usr/bin/caddy
RUN chmod 0755 /usr/bin/caddy && \
    setcap cap_net_bind_service=+ep /usr/bin/caddy

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER smgcaddy
EXPOSE 80 443

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:2019/config/ || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
