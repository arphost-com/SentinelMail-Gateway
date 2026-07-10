-- +goose Up
-- +goose StatementBegin

INSERT INTO user_mail_classifications
  (organization_id, domain_id, user_email, from_addr, subject_fingerprint,
   verdict, sample_count, last_mailbox_message_id, last_mail_log_id,
   last_body_excerpt, created_by, updated_by, created_at, updated_at)
SELECT DISTINCT ON (organization_id, lower(user_email), lower(from_addr))
       organization_id,
       domain_id,
       user_email,
       from_addr,
       '' AS subject_fingerprint,
       verdict,
       sample_count,
       last_mailbox_message_id,
       last_mail_log_id,
       last_body_excerpt,
       created_by,
       updated_by,
       created_at,
       updated_at
  FROM user_mail_classifications
 WHERE verdict IN ('spam', 'phishing', 'malware')
   AND subject_fingerprint <> ''
   AND trim(from_addr) <> ''
 ORDER BY organization_id, lower(user_email), lower(from_addr), updated_at DESC
ON CONFLICT (organization_id, (lower(user_email)), (lower(from_addr)), subject_fingerprint)
DO UPDATE SET
  domain_id = EXCLUDED.domain_id,
  verdict = EXCLUDED.verdict,
  sample_count = GREATEST(user_mail_classifications.sample_count, EXCLUDED.sample_count),
  last_mailbox_message_id = EXCLUDED.last_mailbox_message_id,
  last_mail_log_id = EXCLUDED.last_mail_log_id,
  last_body_excerpt = EXCLUDED.last_body_excerpt,
  updated_by = EXCLUDED.updated_by,
  updated_at = now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- No destructive rollback: these rows are real user spam/phishing/malware
-- training signals once created.

-- +goose StatementEnd
