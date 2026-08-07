-- +goose Up
-- +goose StatementBegin

-- Keep the platform sender separate from tenant support/contact addresses.
-- Hosted operators set this to an address in a domain authenticated by their
-- outbound relay. Empty preserves the legacy self-hosted fallback.
INSERT INTO system_settings (organization_id, key, value)
VALUES (NULL, 'mail.system_from_address', '""'::jsonb)
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM system_settings
WHERE organization_id IS NULL
  AND key = 'mail.system_from_address';

-- +goose StatementEnd
