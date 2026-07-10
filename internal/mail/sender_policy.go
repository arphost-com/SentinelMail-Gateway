package mail

import (
	"context"
	"encoding/json"
	"net/http"
	stdmail "net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
	"github.com/arphost/sentinelmail-gateway/internal/senderlists"
)

type senderPolicyReq struct {
	From    string   `json:"from"`
	ReplyTo string   `json:"reply_to,omitempty"`
	To      []string `json:"to"`
}

type senderPolicyResp struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

func (h *IngestHandler) senderPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := readSignedBody(w, r, h.Secret, 1<<20)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req senderPolicyReq
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(senderListLookupAddresses(req.From, req.ReplyTo)) == 0 || len(req.To) == 0 {
		httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "none"})
		return
	}

	domainID, orgID, err := lookupDomainOrg(r.Context(), h.DB, primaryDomain(req.To[0]))
	if err != nil || orgID == nil {
		httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "none"})
		return
	}
	pol, err := policies.Resolve(r.Context(), h.DB, domainID, orgID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "policy resolve: "+err.Error())
		return
	}
	action, scope, err := h.lookupSenderList(r.Context(), *orgID, domainID, strings.ToLower(strings.TrimSpace(req.To[0])), senderListLookupAddresses(req.From, req.ReplyTo)...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sender policy lookup: "+err.Error())
		return
	}
	switch action {
	case "allow":
		httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "allow", Reason: "sender matched allowlist", Scope: scope})
	case "block":
		if !pol.SenderBlacklistEnabled() {
			httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "none", Reason: "sender blacklist disabled for policy", Scope: scope})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "block", Reason: "sender matched blacklist", Scope: scope})
	default:
		httpx.WriteJSON(w, http.StatusOK, senderPolicyResp{Action: "none"})
	}
}

func (h *IngestHandler) lookupSenderList(ctx context.Context, orgID uuid.UUID, domainID *uuid.UUID, recipient string, addresses ...string) (string, string, error) {
	var allowedScope string
	for _, addr := range senderListLookupAddresses(addresses...) {
		action, scope, err := h.lookupSenderListAddress(ctx, orgID, domainID, recipient, addr)
		if err != nil {
			return "", "", err
		}
		if action == "block" {
			return action, scope, nil
		}
		if action == "allow" && allowedScope == "" {
			allowedScope = scope
		}
	}
	if allowedScope != "" {
		return "allow", allowedScope, nil
	}
	return "", "", nil
}

func (h *IngestHandler) lookupSenderListAddress(ctx context.Context, orgID uuid.UUID, domainID *uuid.UUID, recipient, from string) (string, string, error) {
	patterns := senderlists.PatternsForAddress(from)
	if len(patterns) == 0 {
		return "", "", nil
	}
	var action, scope string
	err := h.DB.QueryRow(ctx, `
		WITH matched_user AS (
			SELECT id FROM users
			 WHERE organization_id = $1
			   AND lower(email::text) = $2
			 LIMIT 1
		)
		SELECT action::text,
		       CASE
		         WHEN user_id IS NOT NULL THEN 'user'
		         WHEN domain_id IS NOT NULL THEN 'domain'
		         WHEN organization_id IS NULL THEN 'system'
		         ELSE 'org'
		       END AS matched_scope
		  FROM list_entries
		 WHERE (organization_id IS NULL OR organization_id = $1)
		   AND lower(pattern) = ANY($4)
		   AND (
		     organization_id IS NULL
		     OR domain_id IS NULL
		     OR domain_id = $3
		     OR action = 'block'::listentry_action
		   )
		   AND (user_id IS NULL OR user_id = (SELECT id FROM matched_user))
		   ORDER BY
		   CASE
		     WHEN user_id IS NOT NULL THEN 0
		     WHEN domain_id = $3 THEN 1
		     WHEN organization_id IS NOT NULL THEN 2
		     WHEN domain_id IS NOT NULL THEN 3
		     ELSE 4
		   END,
		   COALESCE(array_position($4::text[], lower(pattern)), 999),
		   CASE action WHEN 'block' THEN 0 ELSE 1 END,
		   created_at DESC
		 LIMIT 1
	`, orgID, recipient, domainID, patterns).Scan(&action, &scope)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", "", nil
		}
		return "", "", err
	}
	return action, scope, nil
}

func senderListLookupAddresses(values ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		for _, addr := range parseAddressList(value) {
			addr = strings.ToLower(strings.TrimSpace(addr))
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

func parseAddressList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parsed, err := stdmail.ParseAddressList(value); err == nil {
		out := make([]string, 0, len(parsed))
		for _, addr := range parsed {
			out = append(out, addr.Address)
		}
		return out
	}
	if parsed, err := stdmail.ParseAddress(value); err == nil {
		return []string{parsed.Address}
	}
	return []string{strings.Trim(value, "<>")}
}
