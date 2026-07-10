-- +goose Up
-- +goose StatementBegin

CREATE TABLE mail_log_blobs (
    mail_log_id     UUID PRIMARY KEY REFERENCES mail_logs(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    message_bytes   BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_mail_log_blobs_org ON mail_log_blobs(organization_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS mail_log_blobs;

-- +goose StatementEnd
