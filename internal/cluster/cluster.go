// Package cluster exposes MVP 3 multi-node status.
package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
)

type Node struct {
	ID         string          `json:"id"`
	Hostname   string          `json:"hostname"`
	Version    string          `json:"version"`
	LastSeenAt time.Time       `json:"last_seen_at"`
	Metadata   json.RawMessage `json:"metadata"`
}

type Status struct {
	Mode     string    `json:"mode"`
	LocalID  string    `json:"local_id"`
	Hostname string    `json:"hostname"`
	Version  string    `json:"version"`
	Nodes    []Node    `json:"nodes"`
	Checked  time.Time `json:"checked_at"`
}

type Handler struct {
	DB      *pgxpool.Pool
	Version string
}

func Mount(r chi.Router, db *pgxpool.Pool, version string) {
	h := &Handler{DB: db, Version: version}
	r.Get("/status", h.status)
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	if ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "super_admin required")
		return
	}
	hostname, _ := os.Hostname()
	nodeID := firstNonEmpty(lookupString(r.Context(), h.DB, "cluster.node_id"), hostname)
	mode := firstNonEmpty(lookupString(r.Context(), h.DB, "cluster.mode"), "single")
	if err := h.heartbeat(r.Context(), nodeID, hostname); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	nodes, err := h.nodes(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "node list failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Status{
		Mode:     mode,
		LocalID:  nodeID,
		Hostname: hostname,
		Version:  h.Version,
		Nodes:    nodes,
		Checked:  time.Now().UTC(),
	})
}

func (h *Handler) heartbeat(ctx context.Context, nodeID, hostname string) error {
	_, err := h.DB.Exec(ctx, `
		INSERT INTO cluster_nodes (id, hostname, version, last_seen_at, metadata)
		VALUES ($1, $2, $3, now(), '{}'::jsonb)
		ON CONFLICT (id)
		DO UPDATE SET hostname = EXCLUDED.hostname,
		              version = EXCLUDED.version,
		              last_seen_at = now()
	`, nodeID, hostname, h.Version)
	return err
}

func (h *Handler) nodes(ctx context.Context) ([]Node, error) {
	rows, err := h.DB.Query(ctx,
		`SELECT id, hostname, version, last_seen_at, metadata
		   FROM cluster_nodes
		  ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Hostname, &n.Version, &n.LastSeenAt, &n.Metadata); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func lookupString(ctx context.Context, db *pgxpool.Pool, key string) string {
	raw, err := settings.Lookup(ctx, db, key)
	if err != nil || len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
