-- +goose Up
-- +goose StatementBegin

DELETE FROM list_entries le
USING domains d
WHERE le.action = 'block'::listentry_action
  AND (le.pattern LIKE '*@%' OR le.pattern LIKE '@%' OR le.pattern NOT LIKE '%@%')
  AND lower(regexp_replace(regexp_replace(regexp_replace(le.pattern, '^\*@', ''), '^@', ''), '\.$', '')) = lower(d.name::text);

CREATE OR REPLACE FUNCTION prevent_configured_domain_blocklist()
RETURNS trigger AS $$
DECLARE
    normalized_pattern TEXT;
BEGIN
    IF NEW.action = 'block'::listentry_action THEN
        normalized_pattern := lower(btrim(NEW.pattern));
        IF normalized_pattern LIKE '*@%' THEN
            normalized_pattern := substring(normalized_pattern FROM 3);
        ELSIF normalized_pattern LIKE '@%' THEN
            normalized_pattern := substring(normalized_pattern FROM 2);
        ELSIF normalized_pattern LIKE '%@%' THEN
            RETURN NEW;
        END IF;
        normalized_pattern := regexp_replace(normalized_pattern, '\.$', '');

        IF EXISTS (SELECT 1 FROM domains WHERE lower(name::text) = normalized_pattern) THEN
            RAISE EXCEPTION 'cannot block configured protected domain %', normalized_pattern
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_configured_domain_blocklist ON list_entries;
CREATE TRIGGER trg_prevent_configured_domain_blocklist
BEFORE INSERT OR UPDATE OF action, pattern ON list_entries
FOR EACH ROW
EXECUTE FUNCTION prevent_configured_domain_blocklist();

CREATE OR REPLACE FUNCTION remove_blocklists_for_configured_domain()
RETURNS trigger AS $$
BEGIN
    DELETE FROM list_entries
    WHERE action = 'block'::listentry_action
      AND (pattern LIKE '*@%' OR pattern LIKE '@%' OR pattern NOT LIKE '%@%')
      AND lower(regexp_replace(regexp_replace(regexp_replace(pattern, '^\*@', ''), '^@', ''), '\.$', '')) = lower(NEW.name::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_remove_blocklists_for_configured_domain ON domains;
CREATE TRIGGER trg_remove_blocklists_for_configured_domain
AFTER INSERT OR UPDATE OF name ON domains
FOR EACH ROW
EXECUTE FUNCTION remove_blocklists_for_configured_domain();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS trg_remove_blocklists_for_configured_domain ON domains;
DROP FUNCTION IF EXISTS remove_blocklists_for_configured_domain();
DROP TRIGGER IF EXISTS trg_prevent_configured_domain_blocklist ON list_entries;
DROP FUNCTION IF EXISTS prevent_configured_domain_blocklist();

-- +goose StatementEnd
