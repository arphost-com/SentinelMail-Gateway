# syntax=docker/dockerfile:1.7

# ---------- build ----------
FROM node:22-alpine AS build
WORKDIR /src
COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm npm ci || npm install
COPY web/ ./
RUN npm run build

# ---------- runtime ----------
FROM nginx:1.29-alpine
RUN apk upgrade --no-cache && \
    apk add --no-cache --upgrade libxml2 'c-ares>=1.34.8-r0' 'libexpat>=2.8.2-r0' && \
    addgroup -g 10002 -S sentinelweb && \
    adduser -u 10002 -S -G sentinelweb sentinelweb && \
    mkdir -p /var/cache/nginx /var/run /usr/share/nginx/html && \
    chown -R sentinelweb:sentinelweb /var/cache/nginx /var/run /usr/share/nginx/html /etc/nginx
COPY deploy/docker/web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=sentinelweb:sentinelweb /src/dist /usr/share/nginx/html
USER sentinelweb
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
