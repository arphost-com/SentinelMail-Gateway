-- +goose Up
-- +goose StatementBegin

CREATE TABLE mail_campaigns (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id                       UUID REFERENCES domains(id) ON DELETE SET NULL,
    fingerprint                     TEXT NOT NULL,
    bucket_date                     DATE NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')::date,
    sender_key                      TEXT NOT NULL,
    recipient_key                   TEXT NOT NULL,
    normalized_subject              TEXT NOT NULL,
    content_hash                    TEXT NOT NULL,
    threat_class                    TEXT,
    latest_disposition              TEXT NOT NULL,
    message_count                   BIGINT NOT NULL DEFAULT 1,
    unique_source_ips               INTEGER NOT NULL DEFAULT 0,
    suppressed_count                BIGINT NOT NULL DEFAULT 0,
    first_seen                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen                       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_alert_at                   TIMESTAMPTZ,
    representative_mail_log_id      UUID,
    representative_quarantine_id    UUID,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, fingerprint, bucket_date)
);

CREATE INDEX mail_campaigns_org_last_seen
    ON mail_campaigns(organization_id, last_seen DESC);

CREATE TABLE mail_campaign_sources (
    campaign_id UUID NOT NULL REFERENCES mail_campaigns(id) ON DELETE CASCADE,
    client_ip   INET NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    hit_count   BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (campaign_id, client_ip)
);

ALTER TABLE mail_logs
    ADD COLUMN campaign_id UUID REFERENCES mail_campaigns(id) ON DELETE SET NULL,
    ADD COLUMN campaign_copy_number BIGINT;

CREATE INDEX mail_logs_campaign_received
    ON mail_logs(campaign_id, received_at DESC);

ALTER TABLE quarantine_entries
    ADD COLUMN campaign_id UUID REFERENCES mail_campaigns(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX quarantine_entries_campaign_representative
    ON quarantine_entries(campaign_id)
    WHERE campaign_id IS NOT NULL;

ALTER TABLE mail_campaigns
    ADD CONSTRAINT mail_campaigns_representative_mail_log_fk
        FOREIGN KEY (representative_mail_log_id) REFERENCES mail_logs(id) ON DELETE SET NULL,
    ADD CONSTRAINT mail_campaigns_representative_quarantine_fk
        FOREIGN KEY (representative_quarantine_id) REFERENCES quarantine_entries(id) ON DELETE SET NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE mail_campaigns
    DROP CONSTRAINT IF EXISTS mail_campaigns_representative_quarantine_fk,
    DROP CONSTRAINT IF EXISTS mail_campaigns_representative_mail_log_fk;
DROP INDEX IF EXISTS quarantine_entries_campaign_representative;
ALTER TABLE quarantine_entries DROP COLUMN IF EXISTS campaign_id;
DROP INDEX IF EXISTS mail_logs_campaign_received;
ALTER TABLE mail_logs
    DROP COLUMN IF EXISTS campaign_copy_number,
    DROP COLUMN IF EXISTS campaign_id;
DROP TABLE IF EXISTS mail_campaign_sources;
DROP TABLE IF EXISTS mail_campaigns;

-- +goose StatementEnd
