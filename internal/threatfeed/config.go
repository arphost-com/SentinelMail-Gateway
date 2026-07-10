package threatfeed

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FeedConfig mirrors a row in threat_feed_config. Lets operators flip feeds
// on/off and tune intervals from the UI without redeploying.
type FeedConfig struct {
	Feed             string
	Kind             string
	Enabled          bool
	RefreshInterval  time.Duration
	SourceURL        *string
	APIKey           *string
	LastRefreshAt    *time.Time
	LastRefreshOK    *bool
	LastRefreshErr   *string
}

func LoadConfigs(ctx context.Context, db *pgxpool.Pool) ([]FeedConfig, error) {
	rows, err := db.Query(ctx, `
		SELECT feed, kind, enabled, EXTRACT(EPOCH FROM refresh_interval)::bigint,
		       source_url, api_key, last_refresh_at, last_refresh_ok, last_refresh_err
		FROM threat_feed_config
		ORDER BY feed
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FeedConfig{}
	for rows.Next() {
		var fc FeedConfig
		var secs int64
		if err := rows.Scan(&fc.Feed, &fc.Kind, &fc.Enabled, &secs,
			&fc.SourceURL, &fc.APIKey,
			&fc.LastRefreshAt, &fc.LastRefreshOK, &fc.LastRefreshErr); err != nil {
			return nil, err
		}
		fc.RefreshInterval = time.Duration(secs) * time.Second
		out = append(out, fc)
	}
	return out, rows.Err()
}

// recordRefreshStatus updates last_refresh_* so operators can see feed health
// in the UI without trawling logs.
func recordRefreshStatus(ctx context.Context, db *pgxpool.Pool, feed string, ok bool, errStr string) {
	if db == nil {
		return
	}
	if ok {
		_, _ = db.Exec(ctx,
			`UPDATE threat_feed_config
			   SET last_refresh_at = now(), last_refresh_ok = true, last_refresh_err = NULL
			 WHERE feed = $1`, feed)
	} else {
		_, _ = db.Exec(ctx,
			`UPDATE threat_feed_config
			   SET last_refresh_at = now(), last_refresh_ok = false, last_refresh_err = $2
			 WHERE feed = $1`, feed, errStr)
	}
}
