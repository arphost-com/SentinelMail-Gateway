// Package senderlists provides helpers for recipient sender allow/block
// decisions.
package senderlists

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	stdmail "net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/publicsuffix"

	"github.com/arphost/sentinelmail-gateway/internal/audit"
	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Entry struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	DomainID       *uuid.UUID `json:"domain_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	UserEmail      string     `json:"user_email,omitempty"`
	Scope          string     `json:"scope"`
	Action         string     `json:"action"`
	Kind           string     `json:"kind"`
	Pattern        string     `json:"pattern"`
	Sender         string     `json:"sender"`
	SenderDomain   string     `json:"sender_domain"`
	Note           string     `json:"note,omitempty"`
	BlockedCount   int        `json:"blocked_count"`
	CreatedAt      time.Time  `json:"created_at"`
}

func entryCols(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return prefix + `id, ` + prefix + `organization_id, ` + prefix + `domain_id, ` + prefix + `user_id, COALESCE((SELECT u.email::text FROM users u WHERE u.id = ` + prefix + `user_id), ''), ` + prefix + `scope::text, ` + prefix + `action::text, ` + prefix + `kind::text,
                   ` + prefix + `pattern, COALESCE(` + prefix + `note, ''), ` + blockedCountExpr(alias) + `, ` + prefix + `created_at`
}

func blockedCountExpr(alias string) string {
	ref := "list_entries"
	if alias != "" {
		ref = alias
	}
	fromDomain := `lower(trim(both '. ' from substring(COALESCE(ml.from_addr, '') from '@([^@>[:space:]]+)')))`
	return `COALESCE((
		SELECT count(*)
		  FROM mail_logs ml
		 WHERE ` + ref + `.action = 'block'::listentry_action
		   AND ml.received_at >= ` + ref + `.created_at
		   AND lower(COALESCE(ml.reason, '')) = 'sender matched blacklist'
		   AND (` + ref + `.organization_id IS NULL OR ml.organization_id = ` + ref + `.organization_id)
		   AND (` + ref + `.domain_id IS NULL OR ml.domain_id IS NOT DISTINCT FROM ` + ref + `.domain_id)
		   AND (
		     ` + ref + `.user_id IS NULL
		     OR EXISTS (
		       SELECT 1
		         FROM users u
		        WHERE u.id = ` + ref + `.user_id
		          AND (
		            EXISTS (SELECT 1 FROM unnest(ml.to_addrs) AS t WHERE lower(t) = lower(u.email::text))
		            OR EXISTS (
		              SELECT 1
		                FROM mailbox_messages mm
		               WHERE mm.mail_log_id = ml.id
		                 AND lower(mm.to_addr) = lower(u.email::text)
		            )
		          )
		     )
		   )
		   AND CASE WHEN ` + ref + `.kind = 'ip'::listentry_kind THEN
		     ml.client_ip IS NOT NULL AND ml.client_ip <<= ` + ref + `.pattern::cidr
		   ELSE (
		     (lower(` + ref + `.pattern) LIKE '*@%' AND (` + fromDomain + ` = substring(lower(` + ref + `.pattern) from 3) OR ` + fromDomain + ` LIKE '%.' || substring(lower(` + ref + `.pattern) from 3)))
		     OR (lower(` + ref + `.pattern) LIKE '@%' AND (` + fromDomain + ` = substring(lower(` + ref + `.pattern) from 2) OR ` + fromDomain + ` LIKE '%.' || substring(lower(` + ref + `.pattern) from 2)))
		     OR (lower(` + ref + `.pattern) NOT LIKE '%@%' AND (` + fromDomain + ` = lower(` + ref + `.pattern) OR ` + fromDomain + ` LIKE '%.' || lower(` + ref + `.pattern)))
		     OR (lower(` + ref + `.pattern) LIKE '%@%' AND lower(trim(COALESCE(ml.from_addr, ''))) = lower(` + ref + `.pattern))
		   ) END
	), 0)::int`
}

type Handler struct {
	DB *pgxpool.Pool
}

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Delete("/{id}", h.del)
}

func MailLogHasChallengeReason(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID) bool {
	if db == nil || mailLogID == uuid.Nil {
		return false
	}
	var reason string
	if err := db.QueryRow(ctx, `SELECT COALESCE(reason, '') FROM mail_logs WHERE id = $1`, mailLogID).Scan(&reason); err != nil {
		return false
	}
	return challenge.IsPendingReason(reason)
}

func UpsertUserDecision(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, domainID *uuid.UUID, userID uuid.UUID, recipient, fromAddr, action, note string) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid sender decision")
	}
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	fromAddr = normalizeSender(fromAddr)
	if recipient == "" || fromAddr == "" {
		return fmt.Errorf("recipient and sender are required")
	}
	var ok bool
	if err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM users
			 WHERE id = $1
			   AND organization_id = $2
			   AND is_active = true
			   AND lower(email::text) = $3
		)
	`, userID, orgID, recipient).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("recipient user was not found")
	}
	if _, err := db.Exec(ctx, `
		DELETE FROM list_entries
		 WHERE organization_id = $1
		   AND domain_id IS NOT DISTINCT FROM $2
		   AND user_id = $3
		   AND scope = 'user'::listentry_scope
		   AND kind = 'email'::listentry_kind
		   AND lower(pattern) = lower($4)
	`, orgID, domainID, userID, fromAddr); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `
		INSERT INTO list_entries (organization_id, domain_id, user_id, scope, action, kind, pattern, note)
		VALUES ($1, $2, $3, 'user'::listentry_scope, $4::listentry_action, 'email'::listentry_kind, $5, $6)
	`, orgID, domainID, userID, action, fromAddr, note)
	return err
}

func UpsertDecision(ctx context.Context, db *pgxpool.Pool, orgID, domainID, userID *uuid.UUID, scope, kind, value, action, note string) (string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	kind = strings.ToLower(strings.TrimSpace(kind))
	action = strings.ToLower(strings.TrimSpace(action))
	if scope != "system" && scope != "org" && scope != "domain" && scope != "user" {
		return "", fmt.Errorf("scope must be system, org, domain, or user")
	}
	if kind != "email" && kind != "domain" && kind != "ip" {
		return "", fmt.Errorf("kind must be email, domain, or ip")
	}
	if action != "allow" && action != "block" {
		return "", fmt.Errorf("action must be allow or block")
	}
	if kind == "ip" && action != "block" {
		return "", fmt.Errorf("IP rules are block-only")
	}
	if scope != "system" && orgID == nil {
		return "", fmt.Errorf("organization_id is required")
	}
	if scope == "domain" && domainID == nil {
		return "", fmt.Errorf("domain_id is required for domain scope")
	}
	if scope == "user" && userID == nil {
		return "", fmt.Errorf("user_id is required for user scope")
	}
	if scope == "system" {
		orgID, domainID, userID = nil, nil, nil
	} else if scope != "domain" {
		domainID = nil
	}
	if scope != "user" {
		userID = nil
	}
	pattern, err := NormalizeRule(kind, value)
	if err != nil {
		return "", err
	}
	if action == "block" && kind == "domain" {
		protected, err := isConfiguredProtectedDomain(ctx, db, strings.TrimPrefix(pattern, "*@"))
		if err != nil {
			return "", err
		}
		if protected {
			return "", fmt.Errorf("cannot block configured protected domain %s", strings.TrimPrefix(pattern, "*@"))
		}
	}
	if _, err := db.Exec(ctx, `DELETE FROM list_entries
		WHERE organization_id IS NOT DISTINCT FROM $1 AND domain_id IS NOT DISTINCT FROM $2
		  AND user_id IS NOT DISTINCT FROM $3 AND scope = $4::listentry_scope
		  AND kind = $5::listentry_kind AND lower(pattern) = lower($6)`, orgID, domainID, userID, scope, kind, pattern); err != nil {
		return "", err
	}
	_, err = db.Exec(ctx, `INSERT INTO list_entries (organization_id, domain_id, user_id, scope, action, kind, pattern, note)
		VALUES ($1, $2, $3, $4::listentry_scope, $5::listentry_action, $6::listentry_kind, $7, $8)`,
		orgID, domainID, userID, scope, action, kind, pattern, note)
	return pattern, err
}

func NormalizeRule(kind, value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "domain":
		domain, err := NormalizeSenderDomainForPattern(value)
		if err != nil {
			return "", err
		}
		return "*@" + domain, nil
	case "email":
		parsed, err := stdmail.ParseAddress(strings.TrimSpace(value))
		if err != nil || parsed.Address == "" || !strings.Contains(parsed.Address, "@") {
			return "", fmt.Errorf("sender email is invalid")
		}
		return strings.ToLower(parsed.Address), nil
	case "ip":
		value = strings.TrimSpace(value)
		if addr, err := netip.ParseAddr(value); err == nil {
			return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String(), nil
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("source IP or CIDR is invalid")
		}
		return prefix.Masked().String(), nil
	default:
		return "", fmt.Errorf("kind must be email, domain, or ip")
	}
}

func UpsertDomainDecision(ctx context.Context, db *pgxpool.Pool, orgID *uuid.UUID, domainID *uuid.UUID, userID *uuid.UUID, scope, senderDomain, action, note string) (bool, string, error) {
	pattern, err := UpsertDecision(ctx, db, orgID, domainID, userID, scope, "domain", senderDomain, action, note)
	return false, pattern, err
}

func NormalizeSenderDomainPattern(value string) (string, string, error) {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "*@")
	domain = strings.TrimPrefix(domain, "@")
	if strings.Contains(domain, "@") {
		return "", "", fmt.Errorf("sender domain pattern must be a domain or *@domain")
	}
	domain, err := NormalizeSenderDomain(domain)
	if err != nil {
		return "", "", err
	}
	return domain, "*@" + domain, nil
}

func isConfiguredProtectedDomain(ctx context.Context, db *pgxpool.Pool, senderDomain string) (bool, error) {
	senderDomain = strings.ToLower(strings.TrimSpace(senderDomain))
	if senderDomain == "" {
		return false, nil
	}
	var exists bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM domains
			 WHERE lower(name::text) = $1
		)
	`, senderDomain).Scan(&exists)
	return exists, err
}

type writeReq struct {
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	DomainID       *uuid.UUID `json:"domain_id,omitempty"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	Scope          string     `json:"scope"`
	Action         string     `json:"action"`
	Kind           string     `json:"kind,omitempty"`
	Sender         string     `json:"sender,omitempty"`
	SenderDomain   string     `json:"sender_domain"`
	Note           string     `json:"note,omitempty"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	page := httpx.ParsePage(r)
	clauses := []string{}
	args := []any{}
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("(le.organization_id IS NULL OR le.organization_id = ANY($%d))", len(args)))
	}
	if ident.Role == "org_user" {
		args = append(args, ident.UserID)
		clauses = append(clauses, fmt.Sprintf("(le.user_id IS NULL OR le.user_id = $%d)", len(args)))
	}
	if action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action"))); action != "" {
		if action != "allow" && action != "block" {
			httpx.WriteError(w, http.StatusBadRequest, "action must be allow or block")
			return
		}
		args = append(args, action)
		clauses = append(clauses, fmt.Sprintf("le.action = $%d::listentry_action", len(args)))
	}
	if entryScope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope"))); entryScope != "" {
		if entryScope != "system" && entryScope != "org" && entryScope != "domain" && entryScope != "user" {
			httpx.WriteError(w, http.StatusBadRequest, "scope must be system, org, domain, or user")
			return
		}
		args = append(args, entryScope)
		clauses = append(clauses, fmt.Sprintf("le.scope = $%d::listentry_scope", len(args)))
	}
	if userIDRaw := strings.TrimSpace(r.URL.Query().Get("user_id")); userIDRaw != "" {
		userID, err := uuid.Parse(userIDRaw)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
			return
		}
		args = append(args, userID)
		clauses = append(clauses, fmt.Sprintf("le.user_id = $%d", len(args)))
	}
	if domainIDRaw := strings.TrimSpace(r.URL.Query().Get("domain_id")); domainIDRaw != "" {
		domainID, err := uuid.Parse(domainIDRaw)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid domain_id")
			return
		}
		args = append(args, domainID)
		clauses = append(clauses, fmt.Sprintf("(le.organization_id IS NULL OR le.domain_id = $%d)", len(args)))
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		clauses = append(clauses, fmt.Sprintf("(lower(le.pattern) LIKE $%d OR lower(COALESCE(le.note, '')) LIKE $%d OR EXISTS (SELECT 1 FROM users u WHERE u.id = le.user_id AND lower(u.email::text) LIKE $%d))", len(args), len(args), len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), "SELECT count(*) FROM list_entries le"+where, args...).Scan(&total); err != nil {
		slog.Warn("senderlists.count_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "count failed")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := listSQL(where, len(args)-1, len(args))
	items, err := queryEntries(r.Context(), h.DB, sql, args...)
	if err != nil {
		slog.Warn("senderlists.list_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "list failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Entry]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func listSQL(where string, limitArg, offsetArg int) string {
	return `SELECT ` + entryCols("le") + ` FROM list_entries le` + where +
		fmt.Sprintf(` ORDER BY le.created_at DESC LIMIT $%d OFFSET $%d`, limitArg, offsetArg)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Scope = strings.ToLower(strings.TrimSpace(req.Scope))
	if req.Scope == "" {
		req.Scope = "org"
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Kind == "" {
		req.Kind = "domain"
	}
	if strings.TrimSpace(req.Sender) == "" {
		req.Sender = req.SenderDomain
	}

	var orgID *uuid.UUID
	if req.OrganizationID != nil {
		orgID = req.OrganizationID
	} else {
		orgID = &ident.OrganizationID
	}
	domainID := req.DomainID
	userID := req.UserID
	if req.Scope == "system" {
		if ident.Role != "super_admin" {
			httpx.WriteError(w, http.StatusForbidden, "system scope requires super_admin")
			return
		}
		orgID = nil
		domainID = nil
	} else if req.Scope == "domain" {
		if domainID == nil {
			httpx.WriteError(w, http.StatusBadRequest, "domain_id is required for domain scope")
			return
		}
		var domainOrg uuid.UUID
		if err := h.DB.QueryRow(r.Context(), `SELECT organization_id FROM domains WHERE id = $1`, *domainID).Scan(&domainOrg); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
			return
		}
		orgID = &domainOrg
	} else if req.Scope == "user" {
		if userID == nil {
			userID = &ident.UserID
		}
		var userOrg uuid.UUID
		if err := h.DB.QueryRow(r.Context(), `SELECT organization_id FROM users WHERE id = $1 AND is_active = true`, *userID).Scan(&userOrg); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		orgID = &userOrg
	}
	if req.Scope != "domain" {
		domainID = nil
	}
	selfUserRule := req.Scope == "user" && userID != nil && *userID == ident.UserID
	if orgID != nil && !selfUserRule && !scope.CanAdmin(ident.Role, *orgID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	pattern, err := UpsertDecision(r.Context(), h.DB, orgID, domainID, userID, req.Scope, req.Kind, req.Sender, req.Action, strings.TrimSpace(req.Note))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var entry Entry
	if err := scanEntry(h.DB.QueryRow(r.Context(), `
		SELECT `+entryCols("le")+`
		  FROM list_entries le
		 WHERE le.organization_id IS NOT DISTINCT FROM $1
		   AND le.domain_id IS NOT DISTINCT FROM $2
		   AND le.user_id IS NOT DISTINCT FROM $6
		   AND le.scope = $3::listentry_scope
		   AND le.action = $4::listentry_action
		   AND le.kind = $7::listentry_kind
		   AND lower(le.pattern) = lower($5)
		 ORDER BY le.created_at DESC
		 LIMIT 1
	`, orgID, domainID, req.Scope, req.Action, pattern, userID, req.Kind), &entry); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "read created entry failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: uuidValue(orgID),
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "sender_list.create").ActorIP,
		Action:         "sender_list.create",
		TargetKind:     "list_entry",
		TargetID:       entry.ID.String(),
		Detail:         map[string]any{"action": entry.Action, "scope": entry.Scope, "pattern": entry.Pattern, "domain_id": entry.DomainID},
	})
	httpx.WriteJSON(w, http.StatusCreated, entry)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var entry Entry
	if err := scanEntry(h.DB.QueryRow(r.Context(), `SELECT `+entryCols("le")+` FROM list_entries le WHERE le.id = $1`, id), &entry); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	selfUserRule := entry.UserID != nil && *entry.UserID == ident.UserID
	if entry.UserID != nil && !selfUserRule && (entry.OrganizationID == nil || !scope.CanAdmin(ident.Role, *entry.OrganizationID)) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if entry.OrganizationID == nil {
		if ident.Role != "super_admin" {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
	} else if !selfUserRule && !scope.CanAdmin(ident.Role, *entry.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM list_entries WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: uuidValue(entry.OrganizationID),
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "sender_list.delete").ActorIP,
		Action:         "sender_list.delete",
		TargetKind:     "list_entry",
		TargetID:       entry.ID.String(),
		Detail:         map[string]any{"action": entry.Action, "scope": entry.Scope, "pattern": entry.Pattern, "domain_id": entry.DomainID},
	})
	w.WriteHeader(http.StatusNoContent)
}

func uuidValue(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

func queryEntries(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Entry, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var entry Entry
		if err := scanEntry(rows, &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func scanEntry(row pgx.Row, entry *Entry) error {
	var id pgtype.UUID
	var orgID pgtype.UUID
	var domainID pgtype.UUID
	var userID pgtype.UUID
	if err := row.Scan(&id, &orgID, &domainID, &userID, &entry.UserEmail, &entry.Scope, &entry.Action, &entry.Kind, &entry.Pattern, &entry.Note, &entry.BlockedCount, &entry.CreatedAt); err != nil {
		return err
	}
	if !id.Valid {
		return fmt.Errorf("list entry id is null")
	}
	entry.ID = uuid.UUID(id.Bytes)
	entry.OrganizationID = uuidPtrFromPgtype(orgID)
	entry.DomainID = uuidPtrFromPgtype(domainID)
	entry.UserID = uuidPtrFromPgtype(userID)
	entry.SenderDomain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(entry.Pattern)), "*@")
	entry.SenderDomain = strings.TrimPrefix(entry.SenderDomain, "@")
	entry.Sender = entry.SenderDomain
	if entry.Kind == "email" || entry.Kind == "ip" {
		entry.Sender = entry.Pattern
	}
	return nil
}

func uuidPtrFromPgtype(value pgtype.UUID) *uuid.UUID {
	if !value.Valid {
		return nil
	}
	id := uuid.UUID(value.Bytes)
	return &id
}

var senderDomainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func NormalizeSenderDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*@")
	value = strings.TrimPrefix(value, "@")
	if parsed, err := stdmail.ParseAddress(value); err == nil && parsed.Address != "" {
		value = domainPart(parsed.Address)
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, `/\`) {
		return "", fmt.Errorf("sender domain must be a domain name, not a URL or path")
	}
	if !senderDomainRE.MatchString(value) {
		return "", fmt.Errorf("sender domain is invalid")
	}
	return value, nil
}

func NormalizeSenderDomainForPattern(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*@")
	value = strings.TrimPrefix(value, "@")
	if strings.Contains(value, "@") {
		return "", fmt.Errorf("sender domain pattern must be a domain or *@domain")
	}
	return NormalizeSenderDomain(value)
}

func RootSenderDomain(value string) (string, error) {
	domain, err := NormalizeSenderDomain(value)
	if err != nil {
		return "", err
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain, nil
	}
	return strings.ToLower(root), nil
}

func PatternsForAddress(value string) []string {
	addr := normalizeSender(value)
	domain := domainPart(addr)
	if addr == "" || domain == "" {
		return nil
	}
	out := []string{addr}
	for _, candidate := range candidateDomains(domain) {
		out = append(out, "*@"+candidate, candidate, "@"+candidate)
	}
	return uniqueLowerStrings(out)
}

func candidateDomains(domain string) []string {
	domain = strings.ToLower(strings.Trim(domain, ". "))
	if !senderDomainRE.MatchString(domain) {
		return nil
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		root = domain
	}
	root = strings.ToLower(root)
	out := []string{domain}
	current := domain
	for current != root {
		dot := strings.Index(current, ".")
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		current = current[dot+1:]
		out = append(out, current)
	}
	return uniqueLowerStrings(out)
}

func uniqueLowerStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeSender(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := stdmail.ParseAddress(value); err == nil && parsed.Address != "" {
		value = parsed.Address
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func domainPart(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return strings.ToLower(strings.TrimSpace(addr))
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}
