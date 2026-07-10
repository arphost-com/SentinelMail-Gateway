// Package threatfeed ingests external reputation feeds (Spamhaus, URLhaus,
// OpenPhish, SpamCop, …) and exposes a unified Lookup interface.
//
// Design contract: a feed outage MUST NEVER block mail flow. Lookups that
// can't reach a feed return Result{Hit:false}, and the ingester logs the
// failure so operators see it without the gateway losing availability.
package threatfeed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Kind identifies the type of value a feed indexes.
type Kind string

const (
	KindIP     Kind = "ip"
	KindDomain Kind = "domain"
	KindURL    Kind = "url"
	KindHash   Kind = "hash"
)

// Result is what Lookup returns. Hit=false is the safe default.
type Result struct {
	Hit      bool           `json:"hit"`
	Source   string         `json:"source"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Feed is implemented by every threat-intelligence integration.
type Feed interface {
	Name() string
	Kind() Kind
	// Refresh pulls the latest data set. Idempotent. MUST respect ctx.
	Refresh(ctx context.Context) error
	// Lookup returns a Result for the given value. Implementations that
	// can't reach the source return (Result{Hit:false}, nil) so the gateway
	// keeps flowing.
	Lookup(ctx context.Context, value string) (Result, error)
}

// Registry runs ingestion goroutines and exposes a unified Lookup.
type Registry struct {
	log    *slog.Logger
	db     *pgxpool.Pool
	rdb    *redis.Client
	feeds  []Feed
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRegistry constructs a Registry. Feeds are registered separately via Add.
func NewRegistry(log *slog.Logger, db *pgxpool.Pool, rdb *redis.Client) *Registry {
	return &Registry{log: log, db: db, rdb: rdb}
}

// Add registers a feed. Safe to call before Start.
func (r *Registry) Add(f Feed) { r.feeds = append(r.feeds, f) }

// Start kicks off the refresh loop for each feed. Cancel via Stop.
func (r *Registry) Start(parent context.Context) {
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	for _, f := range r.feeds {
		f := f
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.runFeed(ctx, f)
		}()
	}
}

// Stop halts refresh loops; safe to call multiple times.
func (r *Registry) Stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
	r.wg.Wait()
}

func (r *Registry) runFeed(ctx context.Context, f Feed) {
	// Stagger the first refresh slightly so all feeds don't hit upstream
	// services at the same second after a deploy.
	startDelay := time.Duration(len(f.Name())%30) * time.Second
	timer := time.NewTimer(startDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		interval, enabled := r.intervalFor(ctx, f)
		if !enabled {
			timer.Reset(60 * time.Second) // re-check toggle in a minute
			continue
		}
		start := time.Now()
		err := f.Refresh(ctx)
		if err != nil {
			r.log.LogAttrs(ctx, slog.LevelWarn, "threatfeed.refresh_failed",
				slog.String("feed", f.Name()),
				slog.String("err", err.Error()),
				slog.Duration("took", time.Since(start)))
			recordRefreshStatus(ctx, r.db, f.Name(), false, err.Error())
		} else {
			r.log.LogAttrs(ctx, slog.LevelInfo, "threatfeed.refresh_ok",
				slog.String("feed", f.Name()),
				slog.Duration("took", time.Since(start)))
			recordRefreshStatus(ctx, r.db, f.Name(), true, "")
		}
		timer.Reset(interval)
	}
}

// intervalFor pulls the per-feed refresh interval from DB. Falls back to the
// hardcoded default when DB is unreachable or the feed is absent — operators
// flip toggles without redeploying, and a missing DB never wedges the loop.
func (r *Registry) intervalFor(ctx context.Context, f Feed) (time.Duration, bool) {
	if r.db == nil {
		return refreshInterval(f), true
	}
	var enabled bool
	var secs int64
	err := r.db.QueryRow(ctx,
		`SELECT enabled, EXTRACT(EPOCH FROM refresh_interval)::bigint
		 FROM threat_feed_config WHERE feed = $1`, f.Name()).Scan(&enabled, &secs)
	if err != nil {
		return refreshInterval(f), true
	}
	if secs <= 0 {
		secs = int64(refreshInterval(f).Seconds())
	}
	return time.Duration(secs) * time.Second, enabled
}

// Lookup queries every feed of the appropriate kind, returning the first hit.
// Errors from a single feed are downgraded to misses (the contract: don't
// block mail on threat-feed outage).
func (r *Registry) Lookup(ctx context.Context, kind Kind, value string) (Result, error) {
	if value == "" {
		return Result{}, errors.New("empty value")
	}
	cacheKey := fmt.Sprintf("smg:tf:%s:%s", kind, value)
	if hit, ok := r.cacheLookup(ctx, cacheKey); ok {
		return hit, nil
	}
	for _, f := range r.feeds {
		if f.Kind() != kind {
			continue
		}
		if _, enabled := r.intervalFor(ctx, f); !enabled {
			continue
		}
		res, err := f.Lookup(ctx, value)
		if err != nil {
			r.log.LogAttrs(ctx, slog.LevelWarn, "threatfeed.lookup_error",
				slog.String("feed", f.Name()),
				slog.String("value", value),
				slog.String("err", err.Error()))
			continue
		}
		if res.Hit {
			r.cacheStore(ctx, cacheKey, res, 10*time.Minute)
			return res, nil
		}
	}
	miss := Result{Hit: false}
	r.cacheStore(ctx, cacheKey, miss, 60*time.Second)
	return miss, nil
}

func (r *Registry) cacheLookup(ctx context.Context, key string) (Result, bool) {
	if r.rdb == nil {
		return Result{}, false
	}
	v, err := r.rdb.Get(ctx, key).Result()
	if err != nil || v == "" {
		return Result{}, false
	}
	// Tiny encoding: "hit:<source>" or "miss"
	if v == "miss" {
		return Result{Hit: false}, true
	}
	return Result{Hit: true, Source: v[len("hit:"):]}, true
}

func (r *Registry) cacheStore(ctx context.Context, key string, res Result, ttl time.Duration) {
	if r.rdb == nil {
		return
	}
	val := "miss"
	if res.Hit {
		val = "hit:" + res.Source
	}
	_ = r.rdb.Set(ctx, key, val, ttl).Err()
}

// refreshInterval picks an interval per feed type. Hardcoded for MVP; later
// move to per-feed config so operators can tune without redeploys.
func refreshInterval(f Feed) time.Duration {
	switch f.Kind() {
	case KindURL, KindHash:
		return 15 * time.Minute
	case KindDomain:
		return 30 * time.Minute
	case KindIP:
		return 6 * time.Hour
	default:
		return 1 * time.Hour
	}
}
