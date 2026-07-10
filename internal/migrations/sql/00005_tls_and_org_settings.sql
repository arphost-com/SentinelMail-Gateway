-- +goose Up
-- +goose StatementBegin

-- Seed system-wide TLS settings. The Caddy service (task #43) reads these
-- on start. Defaults: off, so a fresh install stays HTTP until the
-- super_admin flips it on. Per-org overrides not supported for TLS — it's
-- a host-level concern.
INSERT INTO system_settings (organization_id, key, value) VALUES
    (NULL, 'tls.mode',         '"off"'::jsonb),
    (NULL, 'tls.hostname',     '""'::jsonb),
    (NULL, 'tls.acme_email',   '""'::jsonb),
    (NULL, 'mail.outbound_relay_host',  '""'::jsonb),
    (NULL, 'mail.outbound_relay_port',  '25'::jsonb)
ON CONFLICT DO NOTHING;

-- Seed per-org default rows for the System org so the UI has something to
-- render even before an org_admin saves anything. Each org's row is
-- created lazily by the PATCH endpoint; this just bootstraps the System
-- org's so the super_admin can see the structure.
INSERT INTO system_settings (organization_id, key, value)
SELECT o.id, k.key, k.value
FROM organizations o
CROSS JOIN (VALUES
    ('brand.name',              '"SentinelMail Gateway"'::jsonb),
    ('brand.support_email',     '""'::jsonb),
    ('alerts.admin_email',      '""'::jsonb),
    ('quarantine.retention_days', '30'::jsonb),
    ('digest.frequency',        '"daily"'::jsonb)
) AS k(key, value)
WHERE o.is_system = true
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM system_settings WHERE key IN (
    'tls.mode', 'tls.hostname', 'tls.acme_email',
    'mail.outbound_relay_host', 'mail.outbound_relay_port',
    'brand.name', 'brand.support_email', 'alerts.admin_email',
    'digest.frequency'
);
-- +goose StatementEnd
