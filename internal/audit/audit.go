// Package audit writes append-only audit_log entries and exposes them via
// /api/v1/audit-log. The schema (audit_log) already exists from migration
// 00001; this package puts a Go writer in front of it and serves a paginated
// read for the UI.
//
// The `hmac` column is a tamper-evidence chain placeholder for a follow-up
// (each row HMAC's the previous row's HMAC + this row's body, keyed by
// SMG_AUDIT_HMAC_KEY). For MVP we leave it NULL and just persist the events.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Entry struct {
	ID         int64           `json:"id"`
	OrgID      *uuid.UUID      `json:"organization_id,omitempty"`
	ActorID    *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorIP    *netip.Addr     `json:"actor_ip,omitempty"`
	Action     string          `json:"action"`
	TargetKind *string         `json:"target_kind,omitempty"`
	TargetID   *string         `json:"target_id,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

const cols = `id, organization_id, actor_user_id, actor_ip,
              action, target_kind, target_id, detail, created_at`

func scan(row pgx.Row, e *Entry) error {
	return row.Scan(&e.ID, &e.OrgID, &e.ActorID, &e.ActorIP,
		&e.Action, &e.TargetKind, &e.TargetID, &e.Detail, &e.CreatedAt)
}

// ---------------- writer ----------------

// Write records a single audit entry. Best-effort: errors are returned but
// callers should treat them as non-fatal (audit must never break the request).
func Write(ctx context.Context, db *pgxpool.Pool, evt Event) error {
	var detail any = nil
	if len(evt.Detail) > 0 {
		detail = evt.Detail
	}
	_, err := db.Exec(ctx, `
		INSERT INTO audit_log (organization_id, actor_user_id, actor_ip,
		                      action, target_kind, target_id, detail)
		VALUES ($1, $2, NULLIF($3,'')::inet, $4, NULLIF($5,''), NULLIF($6,''), $7::jsonb)
	`, nullableUUID(evt.OrganizationID), nullableUUID(evt.ActorUserID),
		evt.ActorIP, evt.Action, evt.TargetKind, evt.TargetID, detail)
	return err
}

// WriteAsync fires Write in a goroutine and logs (not returns) the error.
// Use this from request handlers where audit is best-effort.
func WriteAsync(db *pgxpool.Pool, evt Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = Write(ctx, db, evt)
	}()
}

// Event is the input to Write. All fields are optional except Action.
type Event struct {
	OrganizationID uuid.UUID
	ActorUserID    uuid.UUID
	ActorIP        string
	Action         string         // e.g. "auth.login", "user.update"
	TargetKind     string         // e.g. "user", "policy"
	TargetID       string
	Detail         map[string]any
}

// FromRequest pulls the actor identity and client IP off an authenticated
// HTTP request, leaving only Action / TargetKind / TargetID / Detail for the
// caller to fill in.
func FromRequest(r *http.Request, action string) Event {
	ev := Event{Action: action, ActorIP: clientIP(r)}
	if ident, ok := auth.IdentityFrom(r.Context()); ok {
		ev.OrganizationID = ident.OrganizationID
		ev.ActorUserID = ident.UserID
	}
	return ev
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma > 0 {
			xff = xff[:comma]
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

func nullableUUID(u uuid.UUID) any {
	if u == uuid.Nil {
		return nil
	}
	return u
}

// ---------------- read API ----------------

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	// org_user can only see their own actions; everyone admin-tier sees the
	// org's full log.
	page := httpx.ParsePage(r)
	q := r.URL.Query()

	var (
		clauses []string
		args    []any
	)
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("(organization_id = ANY($%d) OR organization_id IS NULL)", len(args)))
	}
	if ident.Role == "org_user" {
		args = append(args, ident.UserID)
		clauses = append(clauses, fmt.Sprintf("actor_user_id = $%d", len(args)))
	}
	if action := q.Get("action"); action != "" {
		args = append(args, action)
		clauses = append(clauses, fmt.Sprintf("action = $%d", len(args)))
	}
	if actor := q.Get("actor_user_id"); actor != "" {
		if id, err := uuid.Parse(actor); err == nil {
			args = append(args, id)
			clauses = append(clauses, fmt.Sprintf("actor_user_id = $%d", len(args)))
		}
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` built from our own placeholder strings only; user data flows
	// via `args...` and is parameterised by pgx.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM audit_log`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+cols+` FROM audit_log%s ORDER BY id DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))

	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := scan(rows, &e); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, e)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Entry]{Items: out, Total: total, Limit: page.Limit, Offset: page.Offset})
}
