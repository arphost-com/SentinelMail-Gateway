// Package scan dispatches asynchronous content scans (QR phishing, browser
// sandbox, AI scoring, outbound compromise) to the Python worker via Redis,
// and exposes the lifecycle to the UI.
package scan

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/phishingreports"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

// Redis queue routing: the light worker (qr/ai/outbound) and the heavy
// sandbox worker (Playwright + Chromium) each BLPOP a different list, so
// neither blocks the other.
const (
	queueLight   = "smg:scan_jobs"
	queueSandbox = "smg:scan_jobs_sandbox"
)

func queueFor(kind string) string {
	if kind == "sandbox" {
		return queueSandbox
	}
	return queueLight
}

type Job struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	MailLogID      *uuid.UUID      `json:"mail_log_id,omitempty"`
	Kind           string          `json:"kind"`
	State          string          `json:"state"`
	Payload        json.RawMessage `json:"payload"`
	Result         json.RawMessage `json:"result,omitempty"`
	Verdict        *string         `json:"verdict,omitempty"`
	Error          *string         `json:"error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
}

const cols = `id, organization_id, mail_log_id, kind::text, state::text,
              payload, result, verdict, error, created_at, started_at, completed_at`

const listCols = `id, organization_id, mail_log_id, kind::text, state::text,
              CASE
                WHEN kind::text = 'qr' THEN payload - 'image_b64'
                ELSE payload
              END AS payload,
              CASE
                WHEN result IS NULL THEN result
                ELSE result - 'screenshot_b64'
              END AS result,
              verdict, error, created_at, started_at, completed_at`

func scanRow(row pgx.Row, j *Job) error {
	return row.Scan(&j.ID, &j.OrganizationID, &j.MailLogID, &j.Kind, &j.State,
		&j.Payload, &j.Result, &j.Verdict, &j.Error,
		&j.CreatedAt, &j.StartedAt, &j.CompletedAt)
}

var validKinds = map[string]bool{
	"qr": true, "sandbox": true, "ai": true, "outbound": true,
}

type Handler struct {
	DB           *pgxpool.Pool
	Redis        *redis.Client
	IngestSecret []byte // shared with worker for /scan/{id}/result HMAC
}

// MountSession registers the UI-facing routes (list/read/create) on a router
// that already has auth middleware attached.
func MountSession(r chi.Router, db *pgxpool.Pool, rdb *redis.Client, secret []byte) {
	h := &Handler{DB: db, Redis: rdb, IngestSecret: secret}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Get("/{id}", h.read)
}

// MountWorker registers the HMAC-authenticated worker endpoints OUTSIDE the
// session middleware (the worker has no cookie).
func MountWorker(r chi.Router, db *pgxpool.Pool, secret []byte) {
	h := &Handler{DB: db, IngestSecret: secret}
	r.Post("/{id}/result", h.workerResult)
	r.Get("/{id}/payload", h.workerPayload)
}

// workerPayload returns the full job (payload + result so far) for the worker
// to act on. Signed: X-SMG-Signature = hex(hmac-sha256(secret, scan_id)).
func (h *Handler) workerPayload(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	if !h.verifySig([]byte(id.String()), r.Header.Get("X-SMG-Signature")) {
		httpx.WriteError(w, http.StatusUnauthorized, "bad signature")
		return
	}
	var j Job
	if err := scanRow(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM scan_jobs WHERE id = $1`, id), &j); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, j)
}

// ---------------- list ----------------

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	page := httpx.ParsePage(r)
	q := r.URL.Query()

	var (
		clauses []string
		args    []any
	)
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("organization_id = ANY($%d)", len(args)))
	}
	// org_user: only scans whose mail_log was addressed to them. Ad-hoc
	// admin-submitted scans (mail_log_id IS NULL) are hidden from end users.
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		clauses = append(clauses, fmt.Sprintf(
			"mail_log_id IN (SELECT id FROM mail_logs WHERE EXISTS "+
				"(SELECT 1 FROM unnest(to_addrs) AS t WHERE lower(t) = $%d))", len(args)))
	}
	if k := q.Get("kind"); k != "" && validKinds[k] {
		args = append(args, k)
		clauses = append(clauses, fmt.Sprintf("kind = $%d::scan_kind", len(args)))
	}
	if s := q.Get("state"); s != "" {
		args = append(args, s)
		clauses = append(clauses, fmt.Sprintf("state = $%d::scan_state", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` is built from our own placeholder strings only; user data
	// flows via `args...` and is parameterised by pgx.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM scan_jobs`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+listCols+` FROM scan_jobs%s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))

	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err := scanRow(rows, &j); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, j)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Job]{Items: out, Total: total, Limit: page.Limit, Offset: page.Offset})
}

// ---------------- read ----------------

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var j Job
	if err := scanRow(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM scan_jobs WHERE id = $1`, id), &j); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.Allows(j.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, j)
}

// ---------------- create (enqueue) ----------------

type createReq struct {
	Kind      string          `json:"kind"`
	MailLogID *uuid.UUID      `json:"mail_log_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	var req createReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validKinds[req.Kind] {
		httpx.WriteError(w, http.StatusBadRequest, "invalid kind")
		return
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage(`{}`)
	}

	var j Job
	err := scanRow(h.DB.QueryRow(r.Context(), `
		INSERT INTO scan_jobs (organization_id, mail_log_id, kind, payload)
		VALUES ($1, $2, $3::scan_kind, $4::jsonb)
		RETURNING `+cols,
		ident.OrganizationID, req.MailLogID, req.Kind, string(req.Payload)), &j)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "enqueue: "+err.Error())
		return
	}

	// Push a minimal envelope to the worker. The worker pulls the full
	// payload back via GET /scan/{id} so we don't have to inline large
	// base64 blobs into Redis.
	envelope, _ := json.Marshal(map[string]any{
		"scan_id":         j.ID,
		"organization_id": j.OrganizationID,
		"kind":            j.Kind,
	})
	if h.Redis != nil {
		if err := h.Redis.RPush(r.Context(), queueFor(j.Kind), envelope).Err(); err != nil {
			// Job is durably persisted in DB; worker fallback would have to
			// poll DB. Surface this so the UI shows the user something is up.
			_, _ = h.DB.Exec(r.Context(),
				`UPDATE scan_jobs SET state = 'failed', error = $1, completed_at = now() WHERE id = $2`,
				"redis enqueue: "+err.Error(), j.ID)
			httpx.WriteError(w, http.StatusInternalServerError, "queue: "+err.Error())
			return
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, j)
}

// ---------------- worker result callback ----------------

type resultReq struct {
	State   string          `json:"state"`             // "running" | "done" | "failed"
	Verdict string          `json:"verdict,omitempty"` // free-form short label
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func (h *Handler) workerResult(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20)) // 8 MiB cap (sandbox screenshots, OCR text)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "read: "+err.Error())
		return
	}
	if !h.verifySig(body, r.Header.Get("X-SMG-Signature")) {
		httpx.WriteError(w, http.StatusUnauthorized, "bad signature")
		return
	}
	var req resultReq
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	switch req.State {
	case "running":
		_, err = h.DB.Exec(r.Context(),
			`UPDATE scan_jobs SET state = 'running', started_at = COALESCE(started_at, now()) WHERE id = $1`, id)
	case "done":
		_, err = h.DB.Exec(r.Context(), `
			UPDATE scan_jobs SET
			  state = 'done',
			  verdict = NULLIF($2,''),
			  result = $3::jsonb,
			  completed_at = now(),
			  started_at = COALESCE(started_at, now())
			WHERE id = $1
		`, id, req.Verdict, string(nonEmptyOrObject(req.Result)))
	case "failed":
		_, err = h.DB.Exec(r.Context(), `
			UPDATE scan_jobs SET
			  state = 'failed',
			  error = NULLIF($2,''),
			  completed_at = now(),
			  started_at = COALESCE(started_at, now())
			WHERE id = $1
		`, id, req.Error)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "invalid state")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update: "+err.Error())
		return
	}
	if req.State == "done" {
		if err := phishingreports.RecordFromScan(r.Context(), h.DB, id, req.Verdict, nonEmptyOrObject(req.Result)); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "phishing report: "+err.Error())
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) verifySig(body []byte, sigHex string) bool {
	if len(h.IngestSecret) == 0 || sigHex == "" {
		return false
	}
	want := hmac.New(sha256.New, h.IngestSecret)
	want.Write(body)
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return hmac.Equal(want.Sum(nil), got)
}

func nonEmptyOrObject(b []byte) []byte {
	if len(b) == 0 {
		return []byte(`{}`)
	}
	return b
}
