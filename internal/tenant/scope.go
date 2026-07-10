// Package tenant resolves which organizations a caller is allowed to see.
// Hierarchy: an org's parent_id forms a tree; admins of a parent see children.
package tenant

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
)

// Scope describes which org IDs the caller may read or write.
type Scope struct {
	// IsSuperAdmin: unrestricted; all orgs.
	IsSuperAdmin bool
	// OrgID: caller's primary org (always present).
	OrgID uuid.UUID
	// VisibleOrgIDs: descendants + own. nil means "use OrgID only" or
	// (super_admin) "no restriction".
	VisibleOrgIDs []uuid.UUID
}

// Allows returns true if id is within the caller's scope.
func (s Scope) Allows(id uuid.UUID) bool {
	if s.IsSuperAdmin {
		return true
	}
	for _, v := range s.VisibleOrgIDs {
		if v == id {
			return true
		}
	}
	return id == s.OrgID
}

// CanAdmin returns true if the caller can mutate resources within the
// given org (must be admin-tier in their own org or super_admin).
func (s Scope) CanAdmin(role string, id uuid.UUID) bool {
	if s.IsSuperAdmin {
		return true
	}
	if !s.Allows(id) {
		return false
	}
	return role == "super_admin" || role == "msp_admin" || role == "org_admin"
}

// FromContext loads the scope for the authenticated caller from ctx, walking
// the org tree once. Super-admins skip the walk.
func FromContext(ctx context.Context, db *pgxpool.Pool) (*Scope, *auth.Identity, error) {
	ident, ok := auth.IdentityFrom(ctx)
	if !ok {
		return nil, nil, errors.New("no identity in context")
	}
	scope, err := ScopeForIdentity(ctx, db, ident)
	return scope, ident, err
}

func ScopeForIdentity(ctx context.Context, db *pgxpool.Pool, ident *auth.Identity) (*Scope, error) {
	scope := &Scope{OrgID: ident.OrganizationID, IsSuperAdmin: ident.Role == "super_admin"}
	if scope.IsSuperAdmin {
		return scope, nil
	}

	// Walk descendants of the caller's org (BFS via recursive CTE).
	rows, err := db.Query(ctx, `
		WITH RECURSIVE tree(id) AS (
			SELECT id FROM organizations WHERE id = $1
			UNION ALL
			SELECT o.id FROM organizations o JOIN tree t ON o.parent_id = t.id
		)
		SELECT id FROM tree
	`, ident.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		scope.VisibleOrgIDs = append(scope.VisibleOrgIDs, id)
	}
	return scope, rows.Err()
}
