package settings

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type fakeRetentionQuerier struct {
	value int
	err   error
	query string
}

func (q *fakeRetentionQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	q.query = sql
	return fakeRetentionRow{value: q.value, err: q.err}
}

type fakeRetentionRow struct {
	value int
	err   error
}

func (r fakeRetentionRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*int)) = r.value
	return nil
}

func TestMessageRetentionDays(t *testing.T) {
	tests := []struct {
		name  string
		value int
		err   error
		want  int
	}{
		{name: "default when absent", err: pgx.ErrNoRows, want: 90},
		{name: "configured value", value: 45, want: 45},
		{name: "clamps low values", value: -1, want: retentionMinDays},
		{name: "clamps high values", value: 999, want: retentionMaxDays},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &fakeRetentionQuerier{value: tt.value, err: tt.err}
			got := MessageRetentionDays(context.Background(), q, uuid.New())
			if got != tt.want {
				t.Fatalf("MessageRetentionDays() = %d, want %d", got, tt.want)
			}
			if !strings.Contains(q.query, "message.retention_days") {
				t.Fatalf("query did not prefer message.retention_days: %s", q.query)
			}
			if !strings.Contains(q.query, "quarantine.retention_days") {
				t.Fatalf("query did not retain quarantine.retention_days fallback: %s", q.query)
			}
		})
	}
}

func TestRetentionSchemaUsesCombinedMessageKey(t *testing.T) {
	assertHasSetting(t, DefaultKeys, "message.retention_days")
	assertHasSetting(t, DefaultOrgKeys, "message.retention_days")
	assertMissingSetting(t, DefaultKeys, "quarantine.retention_days")
	assertMissingSetting(t, DefaultOrgKeys, "quarantine.retention_days")
}

func assertHasSetting(t *testing.T, metas []SettingMeta, key string) {
	t.Helper()
	for _, meta := range metas {
		if meta.Key == key {
			return
		}
	}
	t.Fatalf("missing setting key %q", key)
}

func assertMissingSetting(t *testing.T, metas []SettingMeta, key string) {
	t.Helper()
	for _, meta := range metas {
		if meta.Key == key {
			t.Fatalf("unexpected setting key %q", key)
		}
	}
}
