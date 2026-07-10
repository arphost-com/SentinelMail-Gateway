-- +goose Up
-- +goose StatementBegin

CREATE TYPE sent_email_status AS ENUM ('pending', 'sent', 'failed');

CREATE TABLE sent_emails (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id           UUID REFERENCES domains(id) ON DELETE SET NULL,
    mail_log_id         UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    quarantine_entry_id UUID REFERENCES quarantine_entries(id) ON DELETE SET NULL,
    kind                TEXT NOT NULL,
    from_addr           TEXT NOT NULL,
    to_addrs            TEXT[] NOT NULL DEFAULT '{}',
    subject             TEXT,
    relay_host          TEXT,
    relay_port          INT,
    status              sent_email_status NOT NULL DEFAULT 'pending',
    error               TEXT,
    raw_message         BYTEA NOT NULL,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    sent_at             TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sent_emails_org_created ON sent_emails(organization_id, created_at DESC);
CREATE INDEX idx_sent_emails_kind_created ON sent_emails(kind, created_at DESC);
CREATE INDEX idx_sent_emails_status_created ON sent_emails(status, created_at DESC);
CREATE INDEX idx_sent_emails_mail_log ON sent_emails(mail_log_id);
CREATE INDEX idx_sent_emails_quarantine ON sent_emails(quarantine_entry_id);
CREATE INDEX idx_sent_emails_to ON sent_emails USING gin(to_addrs);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS sent_emails;
DROP TYPE IF EXISTS sent_email_status;

-- +goose StatementEnd
