-- +goose Up
-- +goose StatementBegin

CREATE TYPE listentry_kind AS ENUM ('email', 'domain', 'ip');

ALTER TABLE list_entries
    ADD COLUMN kind listentry_kind;

UPDATE list_entries
   SET kind = CASE
       WHEN pattern LIKE '%@%' AND pattern NOT LIKE '*@%' AND pattern NOT LIKE '@%' THEN 'email'::listentry_kind
       ELSE 'domain'::listentry_kind
   END;

ALTER TABLE list_entries
    ALTER COLUMN kind SET NOT NULL;

ALTER TABLE users
    ADD COLUMN challenge_response_mode TEXT NOT NULL DEFAULT 'inherit'
        CHECK (challenge_response_mode IN ('inherit', 'enabled', 'disabled'));

ALTER TABLE mail_logs
    ADD COLUMN client_hostname TEXT;

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb) || '{"challenge_response_require_verified_source": true}'::jsonb,
       updated_at = now()
 WHERE NOT COALESCE(settings, '{}'::jsonb) ? 'challenge_response_require_verified_source';

CREATE INDEX idx_list_entries_ip_rules
    ON list_entries (action, pattern)
    WHERE kind = 'ip';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_list_entries_ip_rules;

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb) - 'challenge_response_require_verified_source',
       updated_at = now()
 WHERE COALESCE(settings, '{}'::jsonb) ? 'challenge_response_require_verified_source';

ALTER TABLE mail_logs DROP COLUMN IF EXISTS client_hostname;
ALTER TABLE users DROP COLUMN IF EXISTS challenge_response_mode;
ALTER TABLE list_entries DROP COLUMN IF EXISTS kind;
DROP TYPE IF EXISTS listentry_kind;

-- +goose StatementEnd
