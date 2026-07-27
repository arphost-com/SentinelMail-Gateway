-- +goose Up
-- +goose StatementBegin

ALTER TABLE domains
    ADD COLUMN retention_days INT
    CHECK (retention_days IS NULL OR (retention_days >= 1 AND retention_days <= 365));

ALTER TABLE mailbox_messages
    ADD COLUMN expires_at TIMESTAMPTZ;

UPDATE mailbox_messages mm
   SET expires_at = mm.received_at + (
       COALESCE(
           (SELECT retention_days
              FROM domains d
             WHERE d.id = mm.domain_id
               AND d.retention_days IS NOT NULL),
           (SELECT (value #>> '{}')::int
              FROM system_settings
             WHERE key IN ('message.retention_days', 'quarantine.retention_days')
               AND (organization_id = mm.organization_id OR organization_id IS NULL)
             ORDER BY organization_id IS NULL,
                      CASE key WHEN 'message.retention_days' THEN 0 ELSE 1 END
             LIMIT 1),
           90
       )::int * interval '1 day'
   )
 WHERE mm.expires_at IS NULL;

CREATE INDEX idx_mailbox_messages_expires
    ON mailbox_messages(organization_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_mailbox_messages_expires;
ALTER TABLE mailbox_messages DROP COLUMN IF EXISTS expires_at;
ALTER TABLE domains DROP COLUMN IF EXISTS retention_days;

-- +goose StatementEnd
