-- +goose Up
-- +goose StatementBegin

CREATE TABLE smtp_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE SET NULL,
    queue_id        TEXT,
    event_type      TEXT NOT NULL,
    phase           TEXT,
    direction       TEXT NOT NULL DEFAULT 'inbound',
    from_addr       TEXT,
    to_addr         TEXT,
    client_ip       INET,
    helo            TEXT,
    relay           TEXT,
    status_code     TEXT,
    dsn             TEXT,
    reason          TEXT,
    raw_log         TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (event_type IN ('reject', 'deferred', 'bounced', 'failed', 'tls_error', 'disconnect', 'info'))
);

CREATE INDEX idx_smtp_events_org_time ON smtp_events(organization_id, occurred_at DESC);
CREATE INDEX idx_smtp_events_type_time ON smtp_events(event_type, occurred_at DESC);
CREATE INDEX idx_smtp_events_to_addr ON smtp_events(lower(to_addr), occurred_at DESC);
CREATE INDEX idx_smtp_events_queue ON smtp_events(queue_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS smtp_events;

-- +goose StatementEnd
