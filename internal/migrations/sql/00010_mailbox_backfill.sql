-- +goose Up
-- +goose StatementBegin

INSERT INTO mailbox_messages
  (organization_id, domain_id, mail_log_id, from_addr, to_addr, subject, body_text, received_at, created_at)
SELECT ml.organization_id,
       ml.domain_id,
       ml.id,
       ml.from_addr,
       lower(trim(addr)),
       ml.subject,
       '',
       ml.received_at,
       now()
FROM mail_logs ml
CROSS JOIN LATERAL unnest(ml.to_addrs) AS addr
WHERE trim(addr) <> ''
ON CONFLICT (mail_log_id, to_addr) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM mailbox_messages
WHERE body_text = ''
  AND verdict = 'unreviewed'
  AND verdict_by IS NULL
  AND verdict_at IS NULL;

-- +goose StatementEnd
