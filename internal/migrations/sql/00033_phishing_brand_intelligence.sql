-- +goose Up
-- +goose StatementBegin

CREATE TABLE phishing_brands (
    id               BIGSERIAL PRIMARY KEY,
    slug             TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    aliases          TEXT[] NOT NULL DEFAULT '{}',
    official_domains TEXT[] NOT NULL DEFAULT '{}',
    cues             TEXT[] NOT NULL DEFAULT '{}',
    protected        BOOLEAN NOT NULL DEFAULT FALSE,
    priority         INTEGER NOT NULL DEFAULT 0,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    manually_reviewed_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (slug = lower(slug)),
    CHECK (priority >= 0)
);

CREATE INDEX phishing_brands_active_priority
    ON phishing_brands(active, protected, priority DESC, name);

CREATE TABLE phishing_brand_evidence (
    brand_id          BIGINT NOT NULL REFERENCES phishing_brands(id) ON DELETE CASCADE,
    source            TEXT NOT NULL,
    source_brand_name TEXT NOT NULL,
    observation_count BIGINT NOT NULL DEFAULT 0,
    source_rank       INTEGER,
    first_seen        TIMESTAMPTZ,
    last_seen         TIMESTAMPTZ,
    source_url        TEXT,
    license_note      TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}',
    refreshed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (brand_id, source)
);

CREATE INDEX phishing_brand_evidence_source_rank
    ON phishing_brand_evidence(source, source_rank, observation_count DESC);

INSERT INTO threat_feed_config
    (feed, kind, enabled, refresh_interval, source_url, last_refresh_ok, last_refresh_err)
VALUES
    ('phishtank_brands', 'brand', FALSE, INTERVAL '1 hour',
     'https://data.phishtank.com/data/{app_key}/online-valid.csv.gz',
     FALSE, 'application key not configured')
ON CONFLICT (feed) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM threat_feed_config WHERE feed = 'phishtank_brands';
DROP TABLE IF EXISTS phishing_brand_evidence;
DROP TABLE IF EXISTS phishing_brands;

-- +goose StatementEnd
