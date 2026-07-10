-- +goose Up
-- Admin recovery + impersonation support.
--
-- The impersonator_user_id column flags a session that a super_admin
-- started while impersonating someone else. /auth/impersonate/stop
-- revokes such a session and creates a fresh one for the original user.
-- A nullable column with ON DELETE SET NULL keeps things safe if the
-- admin is later deleted.

ALTER TABLE sessions
    ADD COLUMN impersonator_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_sessions_impersonator
    ON sessions(impersonator_user_id)
    WHERE impersonator_user_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_impersonator;
ALTER TABLE sessions DROP COLUMN IF EXISTS impersonator_user_id;
