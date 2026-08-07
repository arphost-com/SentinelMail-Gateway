// Package brandintel stores and refreshes phishing-brand intelligence used by
// the inbound impersonation detector.
package brandintel

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const builtinSource = "builtin-curated"

//go:embed default_brands.tsv
var defaultBrands string

type Profile struct {
	Name            string   `json:"name"`
	Slug            string   `json:"slug"`
	Aliases         []string `json:"aliases"`
	OfficialDomains []string `json:"official_domains"`
	Cues            []string `json:"cues"`
	Priority        int      `json:"priority"`
}

type seedProfile struct {
	Profile
	Group string
}

// Catalog caches protected profiles briefly so SMTP ingest does not query the
// database for every message. Refreshes and admin edits become active within
// five minutes without putting external lookups in the SMTP path.
type Catalog struct {
	db       *pgxpool.Pool
	mu       sync.RWMutex
	profiles []Profile
	loadedAt time.Time
	ttl      time.Duration
}

func NewCatalog(db *pgxpool.Pool) *Catalog {
	return &Catalog{db: db, ttl: 5 * time.Minute}
}

func (c *Catalog) ProtectedProfiles(ctx context.Context) ([]Profile, error) {
	if c == nil || c.db == nil {
		return nil, nil
	}
	c.mu.RLock()
	if len(c.profiles) > 0 && time.Since(c.loadedAt) < c.ttl {
		out := cloneProfiles(c.profiles)
		c.mu.RUnlock()
		return out, nil
	}
	c.mu.RUnlock()

	rows, err := c.db.Query(ctx, `
		SELECT slug, name, aliases, official_domains, cues, priority
		  FROM phishing_brands
		 WHERE active = true
		   AND protected = true
		   AND cardinality(aliases) > 0
		   AND cardinality(official_domains) > 0
		 ORDER BY priority DESC, name
		 LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Profile, 0, 128)
	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.Slug, &p.Name, &p.Aliases, &p.OfficialDomains, &p.Cues, &p.Priority); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.profiles = cloneProfiles(out)
	c.loadedAt = time.Now()
	c.mu.Unlock()
	return out, nil
}

func (c *Catalog) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.loadedAt = time.Time{}
	c.profiles = nil
	c.mu.Unlock()
}

func cloneProfiles(in []Profile) []Profile {
	out := make([]Profile, len(in))
	for i, p := range in {
		out[i] = p
		out[i].Aliases = append([]string(nil), p.Aliases...)
		out[i].OfficialDomains = append([]string(nil), p.OfficialDomains...)
		out[i].Cues = append([]string(nil), p.Cues...)
	}
	return out
}

// EnsureDefaults loads the independently curated built-in profiles. It is
// idempotent and records provenance separately from the canonical brand row.
func EnsureDefaults(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	profiles, err := parseDefaults(defaultBrands)
	if err != nil {
		return err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, seed := range profiles {
		var brandID int64
		err := tx.QueryRow(ctx, `
			INSERT INTO phishing_brands
				(slug, name, aliases, official_domains, cues, protected, priority)
			VALUES ($1, $2, $3, $4, $5, true, $6)
			ON CONFLICT (slug) DO UPDATE SET
				name = CASE WHEN phishing_brands.manually_reviewed_at IS NULL THEN EXCLUDED.name ELSE phishing_brands.name END,
				aliases = CASE WHEN phishing_brands.manually_reviewed_at IS NULL THEN EXCLUDED.aliases ELSE phishing_brands.aliases END,
				official_domains = CASE WHEN phishing_brands.manually_reviewed_at IS NULL THEN EXCLUDED.official_domains ELSE phishing_brands.official_domains END,
				cues = CASE WHEN phishing_brands.manually_reviewed_at IS NULL THEN EXCLUDED.cues ELSE phishing_brands.cues END,
				protected = CASE WHEN phishing_brands.manually_reviewed_at IS NULL THEN true ELSE phishing_brands.protected END,
				priority = GREATEST(phishing_brands.priority, EXCLUDED.priority),
				updated_at = now()
			RETURNING id
		`, seed.Slug, seed.Name, seed.Aliases, seed.OfficialDomains, seed.Cues, seed.Priority).Scan(&brandID)
		if err != nil {
			return fmt.Errorf("seed brand %s: %w", seed.Slug, err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO phishing_brand_evidence
				(brand_id, source, source_brand_name, source_rank, source_url, license_note, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, jsonb_build_object('cue_group', $7::text))
			ON CONFLICT (brand_id, source) DO UPDATE SET
				source_brand_name = EXCLUDED.source_brand_name,
				source_rank = EXCLUDED.source_rank,
				source_url = EXCLUDED.source_url,
				license_note = EXCLUDED.license_note,
				metadata = EXCLUDED.metadata,
				refreshed_at = now()
		`, brandID, builtinSource, seed.Name, seed.Priority,
			"https://blog.checkpoint.com/research/which-brands-are-impersonated-most-inside-the-q2-2026-brand-phishing-report/",
			"Independently curated brand/domain mapping informed by public vendor reports; no third-party feed records redistributed.",
			seed.Group)
		if err != nil {
			return fmt.Errorf("seed evidence %s: %w", seed.Slug, err)
		}
	}
	return tx.Commit(ctx)
}

func parseDefaults(raw string) ([]seedProfile, error) {
	var out []seedProfile
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 6 {
			return nil, fmt.Errorf("default brand line %d: expected 6 fields", lineNo)
		}
		priority, err := strconv.Atoi(strings.TrimSpace(parts[5]))
		if err != nil || priority < 0 {
			return nil, fmt.Errorf("default brand line %d: invalid priority", lineNo)
		}
		slug := normalizeSlug(parts[0])
		if slug == "" {
			return nil, fmt.Errorf("default brand line %d: empty slug", lineNo)
		}
		if _, ok := seen[slug]; ok {
			return nil, fmt.Errorf("default brand line %d: duplicate slug %s", lineNo, slug)
		}
		seen[slug] = struct{}{}
		group := strings.TrimSpace(parts[4])
		cues, ok := cueGroups[group]
		if !ok {
			return nil, fmt.Errorf("default brand line %d: unknown cue group %s", lineNo, group)
		}
		p := seedProfile{
			Profile: Profile{
				Slug:            slug,
				Name:            strings.TrimSpace(parts[1]),
				Aliases:         splitList(parts[2]),
				OfficialDomains: splitList(parts[3]),
				Cues:            append([]string(nil), cues...),
				Priority:        priority,
			},
			Group: group,
		}
		if p.Name == "" || len(p.Aliases) == 0 || len(p.OfficialDomains) == 0 {
			return nil, fmt.Errorf("default brand line %d: name, aliases, and domains are required", lineNo)
		}
		out = append(out, p)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) < 100 || len(out) > 1000 {
		return nil, fmt.Errorf("default brand count %d outside supported range 100..1000", len(out))
	}
	return out, nil
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		value := strings.ToLower(strings.TrimSpace(part))
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

func normalizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	dash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

var cueGroups = map[string][]string{
	"identity":   {"account", "password", "security", "verify", "verification", "sign in", "login", "subscription", "billing", "storage"},
	"finance":    {"account", "payment", "card", "transaction", "invoice", "refund", "charged", "billing", "verify", "security", "statement"},
	"commerce":   {"account", "order", "shipment", "delivery", "payment", "invoice", "receipt", "refund", "membership", "reward"},
	"delivery":   {"package", "parcel", "shipment", "delivery", "tracking", "address", "postage", "fee", "reschedule"},
	"streaming":  {"account", "payment", "billing", "subscription", "premium", "update", "verify", "sign in", "login", "membership"},
	"social":     {"account", "password", "security", "verify", "verification", "sign in", "login", "message", "business"},
	"crypto":     {"account", "wallet", "seed phrase", "recovery phrase", "verify", "security", "withdrawal", "transaction", "airdrop"},
	"telecom":    {"account", "bill", "billing", "payment", "upgrade", "reward", "verify", "security", "service"},
	"travel":     {"account", "booking", "reservation", "payment", "refund", "cancel", "verify", "itinerary", "reward"},
	"gaming":     {"account", "password", "security", "verify", "sign in", "login", "wallet", "gift", "subscription"},
	"government": {"account", "tax", "refund", "notice", "benefit", "payment", "verify", "identity", "urgent"},
	"business":   {"account", "password", "security", "verify", "sign in", "login", "document", "shared", "invoice", "subscription"},
}
