-- +goose Up
-- +goose StatementBegin

ALTER TABLE users
    ADD COLUMN bulk_completion_notification TEXT NOT NULL DEFAULT 'email'
        CHECK (bulk_completion_notification IN ('email', 'in_app', 'both', 'off'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE users
    DROP COLUMN IF EXISTS bulk_completion_notification;

-- +goose StatementEnd
