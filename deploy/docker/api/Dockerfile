# syntax=docker/dockerfile:1.7

# ---------- build ----------
ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG SMG_VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${SMG_VERSION}" \
      -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
      -o /out/migrate ./cmd/migrate

# ---------- runtime ----------
FROM alpine:3.22
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S sentinel && \
    adduser -u 10001 -S -G sentinel sentinel && \
    mkdir -p /app && chown -R sentinel:sentinel /app
WORKDIR /app
COPY --from=build --chown=sentinel:sentinel /out/api /app/api
COPY --from=build --chown=sentinel:sentinel /out/migrate /app/migrate
USER sentinel
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD ["/app/api", "healthcheck"]
ENTRYPOINT ["/app/api"]
CMD ["serve"]
