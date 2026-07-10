-- +goose Up
-- +goose StatementBegin

CREATE TYPE scan_kind  AS ENUM ('qr', 'sandbox', 'ai', 'outbound');
CREATE TYPE scan_state AS ENUM ('queued', 'running', 'done', 'failed');

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mail_log_id     UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    kind            scan_kind NOT NULL,
    state           scan_state NOT NULL DEFAULT 'queued',
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,   -- input (e.g. base64 image)
    result          JSONB,                                -- worker output (e.g. {decoded_urls, hits, score})
    verdict         TEXT,                                 -- short label: "clean" | "suspicious" | "malicious"
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX scan_jobs_org_state_created ON scan_jobs (organization_id, state, created_at DESC);
CREATE INDEX scan_jobs_state              ON scan_jobs (state) WHERE state IN ('queued', 'running');
CREATE INDEX scan_jobs_mail_log           ON scan_jobs (mail_log_id) WHERE mail_log_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scan_jobs;
DROP TYPE  IF EXISTS scan_state;
DROP TYPE  IF EXISTS scan_kind;
-- +goose StatementEnd
