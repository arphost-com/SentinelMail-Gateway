-- +goose Up
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb)
              || '{"brand_impersonation_enabled": true,
                   "brand_impersonation_display_name_enabled": true,
                   "brand_impersonation_subject_enabled": true,
                   "brand_impersonation_link_mismatch_enabled": true,
                   "brand_impersonation_third_party_receipts_enabled": true}'::jsonb,
       updated_at = now()
 WHERE NOT COALESCE(settings, '{}'::jsonb) ? 'brand_impersonation_enabled';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

UPDATE policies
   SET settings = COALESCE(settings, '{}'::jsonb)
                - 'brand_impersonation_enabled'
                - 'brand_impersonation_display_name_enabled'
                - 'brand_impersonation_subject_enabled'
                - 'brand_impersonation_link_mismatch_enabled'
                - 'brand_impersonation_third_party_receipts_enabled',
       updated_at = now()
 WHERE COALESCE(settings, '{}'::jsonb) ? 'brand_impersonation_enabled';

-- +goose StatementEnd
