-- +goose Up
-- +goose StatementBegin

INSERT INTO system_settings (organization_id, key, value) VALUES
    (NULL, 'ai.mode',                       '"disabled"'::jsonb),
    (NULL, 'deep_analysis.enabled',         'false'::jsonb),
    (NULL, 'deep_analysis.min_score',       '4'::jsonb),
    (NULL, 'deep_analysis.timeout_minutes', '15'::jsonb),
    (NULL, 'threat_intel.cached_enforcement', 'true'::jsonb)
ON CONFLICT (key) WHERE organization_id IS NULL DO NOTHING;

ALTER TABLE mail_logs
    ADD COLUMN deep_analysis_state TEXT NOT NULL DEFAULT 'not_required'
        CHECK (deep_analysis_state IN ('not_required', 'pending', 'releasing', 'released', 'threat', 'unavailable')),
    ADD COLUMN deep_analysis_deadline TIMESTAMPTZ,
    ADD COLUMN deep_analysis_released_at TIMESTAMPTZ,
    ADD COLUMN deep_analysis_failure_reason TEXT;

CREATE INDEX idx_mail_logs_deep_analysis_pending
    ON mail_logs (deep_analysis_deadline)
    WHERE deep_analysis_state = 'pending';

-- These providers have no working runtime lookup implementation. Keeping
-- them in the settings UI implied protection that SentinelMail did not offer.
DELETE FROM threat_feed_config
 WHERE feed IN ('openphish', 'phishtank_brands');

-- The prior false-positive mitigation changed auto-created policies to tag at
-- every high score, including the reject band. Restore a real quarantine at
-- the configured threshold; legitimate mail remains releasable and trainable.
UPDATE policies
   SET quarantine_action = 'quarantine',
       name = replace(name, 'spam tag', 'spam hold'),
       updated_at = now()
 WHERE quarantine_action = 'tag'
   AND settings->>'auto_created' = 'true';

UPDATE system_settings
   SET value = '"quarantine"'::jsonb, updated_at = now()
 WHERE organization_id IS NULL
   AND key = 'quarantine.default_action'
   AND value = '"tag"'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

INSERT INTO threat_feed_config
    (feed, kind, enabled, refresh_interval, source_url, last_refresh_ok, last_refresh_err)
VALUES
    ('openphish', 'url', FALSE, INTERVAL '15 minutes', NULL, NULL, NULL),
    ('phishtank_brands', 'brand', FALSE, INTERVAL '1 hour', 'https://checkurl.phishtank.com/checkurl/', FALSE, 'application key not configured')
ON CONFLICT (feed) DO NOTHING;

UPDATE policies
   SET quarantine_action = 'tag',
       name = replace(name, 'spam hold', 'spam tag'),
       updated_at = now()
 WHERE quarantine_action = 'quarantine'
   AND settings->>'auto_created' = 'true';

UPDATE system_settings
   SET value = '"tag"'::jsonb, updated_at = now()
 WHERE organization_id IS NULL
   AND key = 'quarantine.default_action'
   AND value = '"quarantine"'::jsonb;

DROP INDEX IF EXISTS idx_mail_logs_deep_analysis_pending;
ALTER TABLE mail_logs
    DROP COLUMN IF EXISTS deep_analysis_failure_reason,
    DROP COLUMN IF EXISTS deep_analysis_released_at,
    DROP COLUMN IF EXISTS deep_analysis_deadline,
    DROP COLUMN IF EXISTS deep_analysis_state;

DELETE FROM system_settings
 WHERE organization_id IS NULL
   AND key IN (
       'ai.mode',
       'deep_analysis.enabled',
       'deep_analysis.min_score',
       'deep_analysis.timeout_minutes',
       'threat_intel.cached_enforcement'
   );

-- +goose StatementEnd
