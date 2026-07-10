-- +goose Up
-- +goose StatementBegin

ALTER TABLE users
    ADD COLUMN phishing_alert_frequency TEXT NOT NULL DEFAULT 'weekly'
        CHECK (phishing_alert_frequency IN ('off', 'immediate', 'daily', 'weekly')),
    ADD COLUMN phishing_alert_last_sent_at TIMESTAMPTZ;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE users
    DROP COLUMN IF EXISTS phishing_alert_last_sent_at,
    DROP COLUMN IF EXISTS phishing_alert_frequency;

-- +goose StatementEnd
