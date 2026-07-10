-- +goose Up
-- +goose StatementBegin

ALTER TYPE listentry_scope ADD VALUE IF NOT EXISTS 'system';

ALTER TABLE list_entries
    ALTER COLUMN organization_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_list_entries_system_pattern
    ON list_entries(lower(pattern))
    WHERE organization_id IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM list_entries WHERE organization_id IS NULL;

DROP INDEX IF EXISTS idx_list_entries_system_pattern;

ALTER TABLE list_entries
    ALTER COLUMN organization_id SET NOT NULL;

-- PostgreSQL enum values cannot be removed without rebuilding the type.

-- +goose StatementEnd
