package policies

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hardcodedDefault is the policy used when no DB rows match — keeps the
// gateway safe-by-default even on a freshly migrated empty database.
var hardcodedDefault = Policy{
	Name:                "fallback-default",
	SpamThreshold:       5.0,
	QuarantineThreshold: 10.0,
	RejectThreshold:     15.0,
	DMARCEnforce:        false,
	EnableGreylist:      true,
	QuarantineAction:    "quarantine",
	Settings: map[string]any{
		"source":                                           "hardcoded",
		"sender_blacklist_enabled":                         true,
		"challenge_response_enabled":                       false,
		"brand_impersonation_enabled":                      true,
		"brand_impersonation_display_name_enabled":         true,
		"brand_impersonation_subject_enabled":              true,
		"brand_impersonation_link_mismatch_enabled":        true,
		"brand_impersonation_third_party_receipts_enabled": true,
		"common_scam_detection_enabled":                    true,
		"common_scam_credential_phishing_enabled":          true,
		"common_scam_payment_support_enabled":              true,
		"common_scam_tax_document_enabled":                 true,
		"common_scam_malware_lure_enabled":                 true,
		"common_scam_health_miracle_enabled":               true,
		"common_scam_home_services_enabled":                true,
	},
	IsDefault: true,
}

// Resolve returns the effective policy for a (domain, org) target.
// Precedence: domain-scoped policy → org-scoped policy (walking up the org
// tree via parent_id) → DB row with is_default=true → hardcodedDefault.
func Resolve(ctx context.Context, db *pgxpool.Pool, domainID, orgID *uuid.UUID) (*Policy, error) {
	// 1. Domain-scoped first match wins.
	if domainID != nil {
		p, err := scanOne(ctx, db,
			`SELECT `+cols+` FROM policies WHERE domain_id = $1 ORDER BY updated_at DESC LIMIT 1`,
			*domainID)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	// 2. Walk org tree upward looking for an org-scoped policy.
	if orgID != nil {
		// CTE column is `org_id` (not `id`) so it doesn't collide with
		// policies.id in the final SELECT — would otherwise raise
		// "column reference 'id' is ambiguous".
		p, err := scanOne(ctx, db, `
			WITH RECURSIVE ancestors(org_id, depth) AS (
				SELECT id, 0 FROM organizations WHERE id = $1
				UNION ALL
				SELECT o.parent_id, a.depth + 1
				  FROM organizations o
				  JOIN ancestors a ON a.org_id = o.id
				 WHERE o.parent_id IS NOT NULL
			)
			SELECT `+cols+`
			  FROM policies p
			  JOIN ancestors a ON a.org_id = p.organization_id
			 WHERE p.domain_id IS NULL
			 ORDER BY a.depth ASC, p.updated_at DESC
			 LIMIT 1
		`, *orgID)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	// 3. DB default policy.
	p, err := scanOne(ctx, db,
		`SELECT `+cols+` FROM policies WHERE is_default = true ORDER BY updated_at DESC LIMIT 1`)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	// 4. Hardcoded fallback.
	fallback := hardcodedDefault
	return &fallback, nil
}

func scanOne(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) (*Policy, error) {
	var p Policy
	if err := scan(db.QueryRow(ctx, sql, args...), &p); err != nil {
		return nil, err
	}
	return &p, nil
}
