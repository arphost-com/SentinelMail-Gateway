-- +goose Up
-- +goose StatementBegin

DELETE FROM phishing_reports pr
USING scan_jobs sj
WHERE pr.scan_job_id = sj.id
  AND pr.source = 'scanner'
  AND pr.status = 'auto_verified'
  AND pr.phishing_type = 'browser phishing'
  AND pr.verdict = 'suspicious'
  AND sj.kind = 'sandbox'
  AND EXISTS (
      SELECT 1
        FROM jsonb_array_elements_text(COALESCE(pr.evidence->'reasons', '[]'::jsonb)) AS reason(value)
       WHERE lower(reason.value) LIKE '%redirected to different host%'
  )
  AND COALESCE(jsonb_array_length(COALESCE(pr.evidence->'feed_hits', '[]'::jsonb)), 0) = 0
  AND lower(pr.evidence::text) NOT LIKE '%password input%'
  AND lower(pr.evidence::text) NOT LIKE '%form posts to different domain%'
  AND lower(pr.evidence::text) NOT LIKE '%urlhaus%'
  AND lower(COALESCE(pr.evidence->>'final_url', '')) !~ '(login|signin|sign-in|verify|account|password|secure|review)';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Removed false-positive reports cannot be reconstructed safely.

-- +goose StatementEnd
