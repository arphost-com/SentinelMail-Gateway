-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";    -- case-insensitive email

-- ---------- Organizations (tenants) ----------
CREATE TABLE organizations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    slug          TEXT NOT NULL UNIQUE,
    parent_id     UUID REFERENCES organizations(id) ON DELETE RESTRICT,
    is_system     BOOLEAN NOT NULL DEFAULT FALSE,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_organizations_parent ON organizations(parent_id);

-- ---------- Users ----------
CREATE TYPE user_role AS ENUM ('super_admin', 'msp_admin', 'org_admin', 'org_user');

CREATE TABLE users (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email              CITEXT NOT NULL,
    password_hash      TEXT NOT NULL,
    role               user_role NOT NULL DEFAULT 'org_user',
    display_name       TEXT,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_secret         TEXT,
    mfa_enrolled_at    TIMESTAMPTZ,
    last_login_at      TIMESTAMPTZ,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);
CREATE INDEX idx_users_org ON users(organization_id);

-- ---------- Sessions ----------
CREATE TABLE sessions (
    token_hash      BYTEA PRIMARY KEY,                              -- sha256(token)
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_agent      TEXT,
    ip_addr         INET,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ---------- Domains (managed inbound domains) ----------
CREATE TABLE domains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            CITEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);
CREATE INDEX idx_domains_org ON domains(organization_id);

-- ---------- Gateways (backend MX targets per domain) ----------
CREATE TYPE gateway_kind AS ENUM ('smtp_relay', 'mailcow', 'postfix', 'exchange', 'm365', 'gws');

CREATE TABLE gateways (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind            gateway_kind NOT NULL DEFAULT 'smtp_relay',
    host            TEXT NOT NULL,
    port            INT  NOT NULL DEFAULT 25,
    use_tls         BOOLEAN NOT NULL DEFAULT TRUE,
    priority        INT NOT NULL DEFAULT 10,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_gateways_org    ON gateways(organization_id);
CREATE INDEX idx_gateways_domain ON gateways(domain_id);

-- ---------- Policies (hierarchical: system → org → domain) ----------
CREATE TYPE policy_action AS ENUM ('deliver', 'tag', 'quarantine', 'reject');

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    spam_threshold        NUMERIC(5,2) NOT NULL DEFAULT 5.0,
    quarantine_threshold  NUMERIC(5,2) NOT NULL DEFAULT 10.0,
    reject_threshold      NUMERIC(5,2) NOT NULL DEFAULT 15.0,
    dmarc_enforce         BOOLEAN NOT NULL DEFAULT FALSE,
    enable_greylist       BOOLEAN NOT NULL DEFAULT TRUE,
    quarantine_action     policy_action NOT NULL DEFAULT 'quarantine',
    settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ( (organization_id IS NOT NULL) OR (domain_id IS NOT NULL) OR is_default )
);
CREATE INDEX idx_policies_org    ON policies(organization_id);
CREATE INDEX idx_policies_domain ON policies(domain_id);

-- ---------- Sender allow/block lists ----------
CREATE TYPE listentry_action AS ENUM ('allow', 'block');
CREATE TYPE listentry_scope  AS ENUM ('org', 'domain', 'user');

CREATE TABLE list_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    scope           listentry_scope NOT NULL,
    action          listentry_action NOT NULL,
    pattern         TEXT NOT NULL,   -- e.g. user@example.com or *@example.com
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_list_entries_org     ON list_entries(organization_id);
CREATE INDEX idx_list_entries_pattern ON list_entries(pattern);

-- ---------- Mail logs (one row per message processed) ----------
CREATE TYPE mail_disposition AS ENUM ('delivered', 'tagged', 'quarantined', 'rejected', 'deferred', 'failed');

CREATE TABLE mail_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE SET NULL,
    queue_id        TEXT,
    message_id      TEXT,
    direction       TEXT NOT NULL DEFAULT 'inbound',  -- inbound | outbound
    from_addr       TEXT,
    to_addrs        TEXT[] NOT NULL DEFAULT '{}',
    client_ip       INET,
    helo            TEXT,
    subject         TEXT,
    size_bytes      INT,
    rspamd_score    NUMERIC(6,3),
    rspamd_action   TEXT,
    symbols         JSONB,
    disposition     mail_disposition NOT NULL,
    reason          TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_logs_org_received ON mail_logs(organization_id, received_at DESC);
CREATE INDEX idx_mail_logs_disposition  ON mail_logs(organization_id, disposition, received_at DESC);
CREATE INDEX idx_mail_logs_messageid    ON mail_logs(message_id);

-- ---------- Quarantine ----------
CREATE TYPE quarantine_state AS ENUM ('held', 'released', 'deleted', 'expired');

CREATE TABLE quarantine_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mail_log_id     UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    domain_id       UUID REFERENCES domains(id) ON DELETE SET NULL,
    from_addr       TEXT,
    to_addr         TEXT NOT NULL,
    subject         TEXT,
    rspamd_score    NUMERIC(6,3),
    threat_class    TEXT,                                   -- e.g. PHISHING, SPAM, VIRUS
    storage_key     TEXT NOT NULL,                          -- object-store key for the .eml blob
    size_bytes      INT,
    state           quarantine_state NOT NULL DEFAULT 'held',
    expires_at      TIMESTAMPTZ,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at     TIMESTAMPTZ,
    released_by     UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_quarantine_org_state ON quarantine_entries(organization_id, state, received_at DESC);
CREATE INDEX idx_quarantine_to        ON quarantine_entries(organization_id, to_addr);

-- ---------- Threat feed cache (per-feed entries, refreshed by ingester) ----------
CREATE TABLE threat_feed_entries (
    feed         TEXT NOT NULL,        -- spamhaus_zen, urlhaus, openphish, ...
    value        TEXT NOT NULL,        -- IP, domain, URL, hash
    metadata     JSONB,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    PRIMARY KEY (feed, value)
);
CREATE INDEX idx_threat_feed_expires ON threat_feed_entries(expires_at);

-- ---------- Audit log (append-only) ----------
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip        INET,
    action          TEXT NOT NULL,            -- e.g. auth.login, policy.update
    target_kind     TEXT,                     -- e.g. policy, user, quarantine
    target_id       TEXT,
    detail          JSONB,
    hmac            BYTEA,                    -- tamper-evident chain (set by application layer)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org_created  ON audit_log(organization_id, created_at DESC);
CREATE INDEX idx_audit_actor        ON audit_log(actor_user_id, created_at DESC);
CREATE INDEX idx_audit_action       ON audit_log(action, created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS threat_feed_entries;
DROP TABLE IF EXISTS quarantine_entries;
DROP TYPE  IF EXISTS quarantine_state;
DROP TABLE IF EXISTS mail_logs;
DROP TYPE  IF EXISTS mail_disposition;
DROP TABLE IF EXISTS list_entries;
DROP TYPE  IF EXISTS listentry_scope;
DROP TYPE  IF EXISTS listentry_action;
DROP TABLE IF EXISTS policies;
DROP TYPE  IF EXISTS policy_action;
DROP TABLE IF EXISTS gateways;
DROP TYPE  IF EXISTS gateway_kind;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TYPE  IF EXISTS user_role;
DROP TABLE IF EXISTS organizations;
-- +goose StatementEnd
