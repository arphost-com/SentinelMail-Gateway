// Package config loads runtime configuration from environment variables.
package config

import (
	"context"
	"fmt"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Env             string `env:"SMG_ENV, default=dev"`
	HTTPAddr        string `env:"SMG_HTTP_ADDR, default=:8080"`
	DatabaseURL     string `env:"SMG_DATABASE_URL, required"`
	RedisURL        string `env:"SMG_REDIS_URL, required"`
	SessionSecret   string `env:"SMG_SESSION_SECRET, required"`
	AuditHMACKey    string `env:"SMG_AUDIT_HMAC_KEY, required"`
	IngestHMACKey   string `env:"SMG_INGEST_HMAC_KEY"`
	LogLevel        string `env:"SMG_LOG_LEVEL, default=info"`
	ShutdownTimeout string `env:"SMG_SHUTDOWN_TIMEOUT, default=15s"`
}

func Load(ctx context.Context) (*Config, error) {
	var c Config
	if err := envconfig.Process(ctx, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(c.SessionSecret) < 32 {
		return nil, fmt.Errorf("config: SMG_SESSION_SECRET must be at least 32 chars")
	}
	if len(c.AuditHMACKey) < 32 {
		return nil, fmt.Errorf("config: SMG_AUDIT_HMAC_KEY must be at least 32 chars")
	}
	return &c, nil
}
