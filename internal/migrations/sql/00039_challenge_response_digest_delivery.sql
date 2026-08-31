-- +goose Up
-- +goose StatementBegin

ALTER TABLE users
    ADD COLUMN challenge_response_alert_frequency TEXT NOT NULL DEFAULT 'immediate'
        CHECK (challenge_response_alert_frequency IN ('immediate', 'hourly', 'daily')),
    ADD COLUMN challenge_response_alert_last_attempt_at TIMESTAMPTZ,
    ADD COLUMN challenge_response_alert_last_sent_at TIMESTAMPTZ;

CREATE INDEX idx_users_challenge_response_digest_due
    ON users (challenge_response_alert_frequency, challenge_response_alert_last_sent_at)
    WHERE is_active = true;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_users_challenge_response_digest_due;

ALTER TABLE users
    DROP COLUMN IF EXISTS challenge_response_alert_last_sent_at,
    DROP COLUMN IF EXISTS challenge_response_alert_last_attempt_at,
    DROP COLUMN IF EXISTS challenge_response_alert_frequency;

-- +goose StatementEnd
