package threatfeed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// URLhaus pulls the public abuse.ch URLhaus URL blocklist (~daily refresh upstream).
type URLhaus struct {
	URL    string // override for tests
	Client *http.Client

	mu  sync.RWMutex
	set map[string]struct{}
}

// NewURLhaus returns a feed reading https://urlhaus.abuse.ch/downloads/text/
// (the bare-URL plaintext format).
func NewURLhaus(httpClient *http.Client) *URLhaus {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &URLhaus{
		URL:    "https://urlhaus.abuse.ch/downloads/text/",
		Client: httpClient,
		set:    map[string]struct{}{},
	}
}

func (u *URLhaus) Name() string { return "urlhaus" }
func (u *URLhaus) Kind() Kind   { return KindURL }

func (u *URLhaus) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SentinelMail-Gateway/0.1 (+threatfeed/urlhaus)")
	resp, err := u.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("urlhaus: status %d", resp.StatusCode)
	}

	next := make(map[string]struct{}, 1024)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		next[strings.ToLower(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(next) == 0 {
		return errors.New("urlhaus: empty payload")
	}
	u.mu.Lock()
	u.set = next
	u.mu.Unlock()
	return nil
}

func (u *URLhaus) Lookup(_ context.Context, value string) (Result, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if _, ok := u.set[strings.ToLower(value)]; ok {
		return Result{Hit: true, Source: u.Name()}, nil
	}
	return Result{Hit: false}, nil
}
