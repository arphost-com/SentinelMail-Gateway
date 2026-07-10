-- +goose Up
-- +goose StatementBegin

CREATE TABLE phishing_reports (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id          UUID REFERENCES domains(id) ON DELETE SET NULL,
    mail_log_id        UUID REFERENCES mail_logs(id) ON DELETE SET NULL,
    mailbox_message_id UUID REFERENCES mailbox_messages(id) ON DELETE SET NULL,
    scan_job_id        UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    source             TEXT NOT NULL CHECK (source IN ('scanner', 'user')),
    status             TEXT NOT NULL CHECK (status IN ('auto_verified', 'user_reported')),
    phishing_type      TEXT NOT NULL DEFAULT 'phishing',
    verdict            TEXT NOT NULL DEFAULT '',
    reporter_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    evidence           JSONB NOT NULL DEFAULT '{}'::jsonb,
    reported_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX phishing_reports_scan_job_unique
    ON phishing_reports(scan_job_id)
    WHERE scan_job_id IS NOT NULL;
CREATE UNIQUE INDEX phishing_reports_mailbox_message_unique
    ON phishing_reports(mailbox_message_id)
    WHERE mailbox_message_id IS NOT NULL;
CREATE INDEX phishing_reports_org_reported
    ON phishing_reports(organization_id, reported_at DESC);
CREATE INDEX phishing_reports_org_status
    ON phishing_reports(organization_id, status, reported_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS phishing_reports;

-- +goose StatementEnd
