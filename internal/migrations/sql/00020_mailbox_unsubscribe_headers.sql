-- +goose Up
-- +goose StatementBegin

ALTER TABLE mailbox_messages
    ADD COLUMN list_unsubscribe TEXT,
    ADD COLUMN list_unsubscribe_post TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE mailbox_messages
    DROP COLUMN IF EXISTS list_unsubscribe_post,
    DROP COLUMN IF EXISTS list_unsubscribe;

-- +goose StatementEnd
