package threatfeed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type fakeFeed struct {
	name string
	kind Kind
	res  Result
	err  error
}

func (f *fakeFeed) Name() string                                  { return f.name }
func (f *fakeFeed) Kind() Kind                                    { return f.kind }
func (f *fakeFeed) Refresh(_ context.Context) error               { return nil }
func (f *fakeFeed) Lookup(_ context.Context, _ string) (Result, error) {
	return f.res, f.err
}

func TestLookupReturnsHitFromFirstMatchingFeed(t *testing.T) {
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	r.Add(&fakeFeed{name: "a", kind: KindURL, res: Result{Hit: false}})
	r.Add(&fakeFeed{name: "b", kind: KindURL, res: Result{Hit: true, Source: "b"}})

	got, err := r.Lookup(context.Background(), KindURL, "http://evil.example/")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Hit || got.Source != "b" {
		t.Errorf("expected hit from feed b, got %+v", got)
	}
}

func TestLookupSwallowsFeedErrorsToKeepMailFlowing(t *testing.T) {
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	r.Add(&fakeFeed{name: "broken", kind: KindIP, err: errors.New("network unreachable")})

	got, err := r.Lookup(context.Background(), KindIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup should NOT propagate per-feed errors, got %v", err)
	}
	if got.Hit {
		t.Errorf("expected miss when feed errors, got hit")
	}
}

func TestLookupReturnsMissWhenNoFeedMatchesKind(t *testing.T) {
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	r.Add(&fakeFeed{name: "ips", kind: KindIP, res: Result{Hit: true, Source: "ips"}})

	got, err := r.Lookup(context.Background(), KindURL, "http://x/")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hit {
		t.Errorf("kind mismatch should not return hit, got %+v", got)
	}
}
