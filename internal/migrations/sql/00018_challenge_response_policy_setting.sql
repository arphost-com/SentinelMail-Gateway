-- +goose Up
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb) || '{"challenge_response_enabled": false}'::jsonb,
       updated_at = now()
 WHERE NOT COALESCE(settings, '{}'::jsonb) ? 'challenge_response_enabled';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb) - 'challenge_response_enabled',
       updated_at = now()
 WHERE COALESCE(settings, '{}'::jsonb) ? 'challenge_response_enabled';

-- +goose StatementEnd
