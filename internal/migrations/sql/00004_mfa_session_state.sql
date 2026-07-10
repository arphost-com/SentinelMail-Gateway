-- +goose Up
-- +goose StatementBegin

-- Sessions get an explicit state so the login flow can issue a short-lived
-- pre-MFA session and upgrade it once the TOTP code is verified.
CREATE TYPE session_state AS ENUM ('active', 'mfa_pending');
ALTER TABLE sessions ADD COLUMN state session_state NOT NULL DEFAULT 'active';

-- Pre-MFA sessions are short-lived (5 minutes) and only let the holder
-- call /auth/mfa/verify; index lets the cleaner find them efficiently.
CREATE INDEX sessions_state_expires ON sessions (state, expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS sessions_state_expires;
ALTER TABLE sessions DROP COLUMN IF EXISTS state;
DROP TYPE IF EXISTS session_state;
-- +goose StatementEnd
