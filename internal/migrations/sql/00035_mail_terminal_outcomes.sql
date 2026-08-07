-- +goose Up
-- +goose StatementBegin

ALTER TABLE mail_logs
    ADD COLUMN terminal_action TEXT,
    ADD COLUMN terminal_status_code TEXT,
    ADD COLUMN terminal_reason TEXT,
    ADD COLUMN terminal_relay TEXT,
    ADD COLUMN terminal_at TIMESTAMPTZ,
    ADD COLUMN delivery_mismatch BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT mail_logs_terminal_action_check
        CHECK (terminal_action IS NULL OR terminal_action IN (
            'delivered', 'discarded', 'rejected', 'bounced', 'failed'
        ));

CREATE INDEX idx_mail_logs_delivery_mismatch
    ON mail_logs(organization_id, terminal_at DESC)
    WHERE delivery_mismatch = true;

ALTER TABLE smtp_events
    DROP CONSTRAINT smtp_events_event_type_check,
    ADD CONSTRAINT smtp_events_event_type_check
        CHECK (event_type IN (
            'reject', 'discarded', 'delivered', 'deferred', 'bounced',
            'failed', 'tls_error', 'disconnect', 'info'
        ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE smtp_events
    DROP CONSTRAINT smtp_events_event_type_check,
    ADD CONSTRAINT smtp_events_event_type_check
        CHECK (event_type IN (
            'reject', 'deferred', 'bounced', 'failed',
            'tls_error', 'disconnect', 'info'
        ));

DROP INDEX IF EXISTS idx_mail_logs_delivery_mismatch;

ALTER TABLE mail_logs
    DROP CONSTRAINT IF EXISTS mail_logs_terminal_action_check,
    DROP COLUMN IF EXISTS delivery_mismatch,
    DROP COLUMN IF EXISTS terminal_at,
    DROP COLUMN IF EXISTS terminal_relay,
    DROP COLUMN IF EXISTS terminal_reason,
    DROP COLUMN IF EXISTS terminal_status_code,
    DROP COLUMN IF EXISTS terminal_action;

-- +goose StatementEnd
