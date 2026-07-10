-- +goose Up
-- +goose StatementBegin

ALTER TABLE phishing_reports
    ADD COLUMN quarantine_entry_id UUID REFERENCES quarantine_entries(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX phishing_reports_quarantine_entry_unique
    ON phishing_reports(quarantine_entry_id)
    WHERE quarantine_entry_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS phishing_reports_quarantine_entry_unique;
ALTER TABLE phishing_reports DROP COLUMN IF EXISTS quarantine_entry_id;

-- +goose StatementEnd
