package brandintel

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/threatfeed"
)

const (
	phishTankFeedName   = "phishtank_brands"
	phishTankBaseURL    = "https://data.phishtank.com/data/"
	maxPhishTankBytes   = 256 << 20
	maxImportedTargets  = 1000
	phishTankLicenseURL = "https://www.phishtank.com/developer_info.php"
)

type targetObservation struct {
	Name      string
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

type PhishTankFeed struct {
	db     *pgxpool.Pool
	client *http.Client
}

func NewPhishTankFeed(db *pgxpool.Pool, client *http.Client) *PhishTankFeed {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	return &PhishTankFeed{db: db, client: client}
}

func (f *PhishTankFeed) Name() string          { return phishTankFeedName }
func (f *PhishTankFeed) Kind() threatfeed.Kind { return threatfeed.KindBrand }
func (f *PhishTankFeed) Lookup(context.Context, string) (threatfeed.Result, error) {
	return threatfeed.Result{Hit: false, Source: phishTankFeedName}, nil
}

func (f *PhishTankFeed) Refresh(ctx context.Context) error {
	if f == nil || f.db == nil {
		return errors.New("database unavailable")
	}
	var apiKey *string
	if err := f.db.QueryRow(ctx, `
		SELECT api_key
		  FROM threat_feed_config
		 WHERE feed = $1
	`, phishTankFeedName).Scan(&apiKey); err != nil {
		return fmt.Errorf("load PhishTank configuration: %w", err)
	}
	key := ""
	if apiKey != nil {
		key = strings.TrimSpace(*apiKey)
	}
	if key == "" {
		return errors.New("PhishTank application key is not configured")
	}
	feedURL := phishTankBaseURL + url.PathEscape(key) + "/online-valid.csv.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SentinelMail-Gateway/1.0 (phishing-brand intelligence)")
	req.Header.Set("Accept", "application/gzip,text/csv")
	resp, err := f.client.Do(req)
	if err != nil {
		// net/http errors include the request URL. That URL contains the
		// application key, so never persist or display the wrapped error.
		return errors.New("download PhishTank feed: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download PhishTank feed: HTTP %d", resp.StatusCode)
	}
	reader, err := gzip.NewReader(io.LimitReader(resp.Body, maxPhishTankBytes))
	if err != nil {
		return fmt.Errorf("open PhishTank gzip: %w", err)
	}
	defer reader.Close()
	observations, err := parsePhishTankCSV(reader)
	if err != nil {
		return err
	}
	return f.store(ctx, observations)
}

func parsePhishTankCSV(reader io.Reader) ([]targetObservation, error) {
	csvReader := csv.NewReader(io.LimitReader(reader, maxPhishTankBytes))
	csvReader.ReuseRecord = true
	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("read PhishTank header: %w", err)
	}
	index := map[string]int{}
	for i, name := range header {
		index[strings.ToLower(strings.TrimSpace(name))] = i
	}
	targetIndex, ok := index["target"]
	if !ok {
		return nil, errors.New("PhishTank feed is missing target column")
	}
	submittedIndex := index["submission_time"]
	observed := map[string]*targetObservation{}
	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read PhishTank record: %w", err)
		}
		if targetIndex >= len(record) {
			continue
		}
		name := normalizeTargetName(record[targetIndex])
		if name == "" {
			continue
		}
		slug := normalizeSlug(name)
		if slug == "" {
			continue
		}
		item := observed[slug]
		if item == nil {
			item = &targetObservation{Name: name}
			observed[slug] = item
		}
		item.Count++
		if submittedIndex >= 0 && submittedIndex < len(record) {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(record[submittedIndex])); err == nil {
				if item.FirstSeen.IsZero() || parsed.Before(item.FirstSeen) {
					item.FirstSeen = parsed
				}
				if item.LastSeen.IsZero() || parsed.After(item.LastSeen) {
					item.LastSeen = parsed
				}
			}
		}
	}
	out := make([]targetObservation, 0, len(observed))
	for _, item := range observed {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > maxImportedTargets {
		out = out[:maxImportedTargets]
	}
	return out, nil
}

func normalizeTargetName(raw string) string {
	value := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	switch strings.ToLower(value) {
	case "", "other", "unknown", "generic", "n/a", "na", "none", "unavailable":
		return ""
	default:
		return value
	}
}

func (f *PhishTankFeed) store(ctx context.Context, observations []targetObservation) error {
	tx, err := f.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for rank, observation := range observations {
		slug := normalizeSlug(observation.Name)
		var brandID int64
		err := tx.QueryRow(ctx, `
			INSERT INTO phishing_brands
				(slug, name, aliases, protected, priority)
			VALUES ($1, $2, ARRAY[lower($2)], false, 0)
			ON CONFLICT (slug) DO UPDATE SET
				updated_at = now()
			RETURNING id
		`, slug, observation.Name).Scan(&brandID)
		if err != nil {
			return fmt.Errorf("upsert PhishTank brand %s: %w", slug, err)
		}
		metadata := map[string]any{
			"feed_scope":      "verified online phishing URLs",
			"import_position": rank + 1,
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO phishing_brand_evidence
				(brand_id, source, source_brand_name, observation_count, source_rank,
				 first_seen, last_seen, source_url, license_note, metadata, refreshed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
			ON CONFLICT (brand_id, source) DO UPDATE SET
				source_brand_name = EXCLUDED.source_brand_name,
				observation_count = EXCLUDED.observation_count,
				source_rank = EXCLUDED.source_rank,
				first_seen = EXCLUDED.first_seen,
				last_seen = EXCLUDED.last_seen,
				source_url = EXCLUDED.source_url,
				license_note = EXCLUDED.license_note,
				metadata = EXCLUDED.metadata,
				refreshed_at = now()
		`, brandID, phishTankFeedName, observation.Name, observation.Count, rank+1,
			nullTime(observation.FirstSeen), nullTime(observation.LastSeen),
			phishTankLicenseURL,
			"PhishTank verified feed target field; application key and Cisco/PhishTank terms apply.",
			metadata)
		if err != nil {
			return fmt.Errorf("upsert PhishTank evidence %s: %w", slug, err)
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE threat_feed_config
		   SET last_refresh_err = NULL,
		       updated_at = now()
		 WHERE feed = $1
	`, phishTankFeedName)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
