-- +goose Up
-- +goose StatementBegin

UPDATE policies
   SET quarantine_action = 'tag',
       name = replace(name, 'spam hold', 'spam tag'),
       updated_at = now()
 WHERE quarantine_action = 'quarantine'
   AND settings->>'auto_created' = 'true';

UPDATE system_settings
   SET value = '"tag"'::jsonb,
       updated_at = now()
 WHERE organization_id IS NULL
   AND key = 'quarantine.default_action'
   AND value = '"quarantine"'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE policies
   SET quarantine_action = 'quarantine',
       name = replace(name, 'spam tag', 'spam hold'),
       updated_at = now()
 WHERE quarantine_action = 'tag'
   AND settings->>'auto_created' = 'true';

UPDATE system_settings
   SET value = '"quarantine"'::jsonb,
       updated_at = now()
 WHERE organization_id IS NULL
   AND key = 'quarantine.default_action'
   AND value = '"tag"'::jsonb;

-- +goose StatementEnd
