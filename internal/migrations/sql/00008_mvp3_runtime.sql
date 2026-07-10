-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS billing_webhook_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        TEXT NOT NULL,
    event_type      TEXT,
    external_id     TEXT,
    payload         JSONB NOT NULL,
    signature_valid BOOLEAN NOT NULL DEFAULT TRUE,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_received
    ON billing_webhook_events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_provider
    ON billing_webhook_events(provider, received_at DESC);

CREATE TABLE IF NOT EXISTS cluster_nodes (
    id            TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL,
    version       TEXT NOT NULL DEFAULT '',
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_cluster_nodes_seen
    ON cluster_nodes(last_seen_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS cluster_nodes;
DROP TABLE IF EXISTS billing_webhook_events;

-- +goose StatementEnd
