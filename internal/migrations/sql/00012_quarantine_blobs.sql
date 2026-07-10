-- +goose Up
-- +goose StatementBegin

CREATE TABLE quarantine_blobs (
    quarantine_entry_id UUID PRIMARY KEY REFERENCES quarantine_entries(id) ON DELETE CASCADE,
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mail_log_id         UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    message_bytes       BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_quarantine_blobs_org ON quarantine_blobs(organization_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS quarantine_blobs;

-- +goose StatementEnd
