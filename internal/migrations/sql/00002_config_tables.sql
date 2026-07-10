-- +goose Up
-- +goose StatementBegin

-- ---------- system_settings ----------
-- Generic key/value runtime configuration. organization_id NULL = global.
-- Values are JSONB to keep typed lists/objects without separate tables.
-- Surrogate PK because composite (org_id, key) can't allow NULL org_id.
-- Uniqueness is enforced by two partial unique indexes: one for global
-- rows (org_id IS NULL) and one for per-org rows (org_id IS NOT NULL).
CREATE TABLE system_settings (
    id              BIGSERIAL PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    value           JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX system_settings_global_key
    ON system_settings (key)
    WHERE organization_id IS NULL;
CREATE UNIQUE INDEX system_settings_org_key
    ON system_settings (organization_id, key)
    WHERE organization_id IS NOT NULL;

-- Seed reasonable defaults so the UI always has a value to show.
INSERT INTO system_settings (organization_id, key, value) VALUES
    (NULL, 'mail.hostname',                   '"mx.example.com"'::jsonb),
    (NULL, 'mail.mynetworks',                 '"127.0.0.0/8 10.0.0.0/8 172.16.0.0/12"'::jsonb),
    (NULL, 'quarantine.retention_days',       '30'::jsonb),
    (NULL, 'quarantine.default_action',       '"quarantine"'::jsonb),
    (NULL, 'ui.brand_name',                   '"SentinelMail Gateway"'::jsonb);

-- ---------- threat_feed_config ----------
-- Operator-controllable per-feed runtime config. The registry reads this on
-- start (and on UI toggle) instead of being hardcoded in cmd/api/main.go.
CREATE TABLE threat_feed_config (
    feed              TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,                          -- ip | domain | url | hash
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_interval  INTERVAL NOT NULL DEFAULT INTERVAL '1 hour',
    source_url        TEXT,                                   -- for bulk feeds
    api_key           TEXT,                                   -- nullable; usually only for paid feeds
    last_refresh_at   TIMESTAMPTZ,
    last_refresh_ok   BOOLEAN,
    last_refresh_err  TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO threat_feed_config (feed, kind, enabled, refresh_interval, source_url) VALUES
    ('spamhaus_zen', 'ip',     TRUE, INTERVAL '6 hours',  'zen.spamhaus.org'),
    ('spamhaus_dbl', 'domain', TRUE, INTERVAL '30 minutes', 'dbl.spamhaus.org'),
    ('spamcop',      'ip',     TRUE, INTERVAL '6 hours',  'bl.spamcop.net'),
    ('urlhaus',      'url',    TRUE, INTERVAL '15 minutes', 'https://urlhaus.abuse.ch/downloads/text/'),
    ('openphish',    'url',    FALSE, INTERVAL '15 minutes', NULL);

-- ---------- user-mgmt: nothing to add — schema already covers role, mfa, active.
-- (Kept here as a doc anchor so future migrations are easy to find.)

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threat_feed_config;
DROP INDEX IF EXISTS system_settings_org_key;
DROP INDEX IF EXISTS system_settings_global_key;
DROP TABLE IF EXISTS system_settings;
-- +goose StatementEnd
