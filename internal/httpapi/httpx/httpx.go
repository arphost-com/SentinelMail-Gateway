// Package httpx provides small helpers used across handler packages.
package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxBodyBytes caps incoming JSON bodies for safety; tune later if needed.
const MaxBodyBytes = 1 << 20 // 1 MiB

// WriteJSON encodes v with the given status. Errors during encoding are logged
// to stderr-ish by the recoverer; we don't try to fix mid-stream failures.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError emits a normalized {error,code} JSON envelope.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": msg, "code": status})
}

// DecodeJSON reads a JSON body into dst with a size cap and strict field check.
func DecodeJSON(r *http.Request, w http.ResponseWriter, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("extra JSON content after top-level value")
	}
	return nil
}

// ParseUUID returns the parsed UUID or writes a 400 and returns the zero value.
func ParseUUID(w http.ResponseWriter, s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

// IsNotFound returns true for pgx no-rows errors so handlers can convert to 404.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// Page captures common pagination input.
type Page struct {
	Limit  int
	Offset int
}

// ParsePage reads ?limit & ?offset from r, clamping to safe values.
func ParsePage(r *http.Request) Page {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return Page{Limit: limit, Offset: offset}
}

// List envelope returned by every list endpoint.
type List[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
