-- +goose Up
-- +goose StatementBegin

UPDATE system_settings
   SET value = '90'::jsonb,
       updated_at = now()
 WHERE key = 'quarantine.retention_days'
   AND value = '30'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE system_settings
   SET value = '30'::jsonb,
       updated_at = now()
 WHERE key = 'quarantine.retention_days'
   AND value = '90'::jsonb;

-- +goose StatementEnd
