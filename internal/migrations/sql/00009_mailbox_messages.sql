-- +goose Up
-- +goose StatementBegin

CREATE TABLE mailbox_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE SET NULL,
    mail_log_id     UUID NOT NULL REFERENCES mail_logs(id) ON DELETE CASCADE,
    from_addr       TEXT,
    to_addr         TEXT NOT NULL,
    subject         TEXT,
    body_text       TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (verdict IN ('unreviewed', 'not_spam', 'spam', 'phishing', 'malware', 'other')),
    verdict_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    verdict_at      TIMESTAMPTZ,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mail_log_id, to_addr)
);
CREATE INDEX idx_mailbox_messages_recipient
    ON mailbox_messages(organization_id, lower(to_addr), received_at DESC);
CREATE INDEX idx_mailbox_messages_verdict
    ON mailbox_messages(organization_id, verdict, received_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS mailbox_messages;

-- +goose StatementEnd
