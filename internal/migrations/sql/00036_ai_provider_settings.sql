-- +goose Up
-- +goose StatementBegin

INSERT INTO system_settings (organization_id, key, value) VALUES
    (NULL, 'ai.provider',          '"anthropic"'::jsonb),
    (NULL, 'ai.model',             '""'::jsonb),
    (NULL, 'ai.anthropic_api_key', '""'::jsonb),
    (NULL, 'ai.openai_api_key',    '""'::jsonb)
ON CONFLICT (key) WHERE organization_id IS NULL DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM system_settings
 WHERE organization_id IS NULL
   AND key IN ('ai.provider', 'ai.model', 'ai.anthropic_api_key', 'ai.openai_api_key');

-- +goose StatementEnd
