-- +goose Up
-- +goose StatementBegin

-- message.retention_days supersedes quarantine.retention_days and applies to
-- both delivered inbox copies and quarantine rows. Seed it from the legacy key
-- where present so upgrades preserve the operator's existing retention window.
WITH global_retention AS (
    SELECT COALESCE(
        (SELECT value FROM system_settings WHERE organization_id IS NULL AND key = 'message.retention_days'),
        (SELECT value FROM system_settings WHERE organization_id IS NULL AND key = 'quarantine.retention_days'),
        '90'::jsonb
    ) AS value
)
INSERT INTO system_settings (organization_id, key, value)
SELECT NULL, 'message.retention_days', value
  FROM global_retention
ON CONFLICT (key) WHERE organization_id IS NULL DO NOTHING;

INSERT INTO system_settings (organization_id, key, value)
SELECT organization_id, 'message.retention_days', value
  FROM system_settings
 WHERE organization_id IS NOT NULL
   AND key = 'quarantine.retention_days'
ON CONFLICT (organization_id, key) WHERE organization_id IS NOT NULL DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM system_settings WHERE key = 'message.retention_days';

-- +goose StatementEnd
