-- +goose Up
-- +goose StatementBegin

INSERT INTO system_settings (organization_id, key, value) VALUES
    (NULL, 'link_rewrite.enabled',        'false'::jsonb),
    (NULL, 'link_rewrite.public_base_url','""'::jsonb),
    (NULL, 'sso.enabled',                 'false'::jsonb),
    (NULL, 'sso.provider',                '"oidc"'::jsonb),
    (NULL, 'sso.issuer_url',              '""'::jsonb),
    (NULL, 'sso.client_id',               '""'::jsonb),
    (NULL, 'billing.provider',            '"none"'::jsonb),
    (NULL, 'billing.webhooks_enabled',    'false'::jsonb),
    (NULL, 'cluster.mode',                '"single"'::jsonb),
    (NULL, 'cluster.node_id',             '""'::jsonb)
ON CONFLICT DO NOTHING;

INSERT INTO system_settings (organization_id, key, value)
SELECT o.id, 'billing.customer_ref', '""'::jsonb
FROM organizations o
WHERE o.is_system = true
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM system_settings WHERE key IN (
    'link_rewrite.enabled',
    'link_rewrite.public_base_url',
    'sso.enabled',
    'sso.provider',
    'sso.issuer_url',
    'sso.client_id',
    'billing.provider',
    'billing.webhooks_enabled',
    'cluster.mode',
    'cluster.node_id',
    'billing.customer_ref'
);

-- +goose StatementEnd
