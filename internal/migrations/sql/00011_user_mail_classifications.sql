-- +goose Up
-- +goose StatementBegin

CREATE TABLE user_mail_classifications (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id               UUID REFERENCES domains(id) ON DELETE SET NULL,
    user_email              TEXT NOT NULL,
    from_addr               TEXT NOT NULL DEFAULT '',
    subject_fingerprint     TEXT NOT NULL DEFAULT '',
    verdict                 TEXT NOT NULL
                            CHECK (verdict IN ('not_spam', 'spam', 'phishing', 'malware', 'other')),
    sample_count            INT NOT NULL DEFAULT 1,
    last_mailbox_message_id UUID REFERENCES mailbox_messages(id) ON DELETE SET NULL,
    last_mail_log_id        UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    last_body_excerpt       TEXT NOT NULL DEFAULT '',
    created_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX user_mail_classifications_unique_key
    ON user_mail_classifications(organization_id, lower(user_email), lower(from_addr), subject_fingerprint);
CREATE INDEX idx_user_mail_classifications_lookup
    ON user_mail_classifications(organization_id, lower(user_email), lower(from_addr), subject_fingerprint);
CREATE INDEX idx_user_mail_classifications_sender
    ON user_mail_classifications(organization_id, lower(user_email), lower(from_addr), verdict);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS user_mail_classifications;

-- +goose StatementEnd
