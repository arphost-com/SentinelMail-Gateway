-- +goose Up
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb)
              || '{"common_scam_detection_enabled": true,
                   "common_scam_credential_phishing_enabled": true,
                   "common_scam_payment_support_enabled": true,
                   "common_scam_tax_document_enabled": true,
                   "common_scam_malware_lure_enabled": true,
                   "common_scam_health_miracle_enabled": true,
                   "common_scam_home_services_enabled": true}'::jsonb,
       updated_at = now()
 WHERE NOT COALESCE(settings, '{}'::jsonb) ? 'common_scam_detection_enabled';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb)
                - 'common_scam_detection_enabled'
                - 'common_scam_credential_phishing_enabled'
                - 'common_scam_payment_support_enabled'
                - 'common_scam_tax_document_enabled'
                - 'common_scam_malware_lure_enabled'
                - 'common_scam_health_miracle_enabled'
                - 'common_scam_home_services_enabled',
       updated_at = now()
 WHERE COALESCE(settings, '{}'::jsonb) ? 'common_scam_detection_enabled';

-- +goose StatementEnd
