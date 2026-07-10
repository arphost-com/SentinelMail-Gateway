import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../../api/client";
import { Button } from "../../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../../components/ui/Card";
import { Field } from "../../components/ui/Field";
import { HelpTooltip } from "../../components/ui/HelpTooltip";
import { Input } from "../../components/ui/Input";

interface FeedDTO {
  feed: string;
  kind: string;
  enabled: boolean;
  refresh_seconds: number;
  source_url?: string;
  has_api_key: boolean;
  last_refresh_at?: string;
  last_refresh_ok?: boolean;
  last_refresh_err?: string;
}

interface FeedsResp { items: FeedDTO[] }

export function ThreatFeedsTab() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["threat-feeds"],
    queryFn: () => api.get<FeedsResp>("/threat-feeds"),
    refetchInterval: 60_000,
  });
  const mut = useMutation({
    mutationFn: ({ feed, patch }: { feed: string; patch: Record<string, unknown> }) =>
      api.patch<FeedsResp>(`/threat-feeds/${feed}`, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["threat-feeds"] }),
  });

  if (isLoading) return <div className="text-sm text-subtle">Loading…</div>;
  if (error) return <div role="alert" className="text-sm text-danger">{error instanceof Error ? error.message : "Failed to load"}</div>;
  if (!data) return null;
  const enabled = data.items.filter((feed) => feed.enabled).length;
  const errors = data.items.filter((feed) => feed.last_refresh_ok === false).length;

  return (
    <div className="grid gap-3">
      <div className="grid gap-3 md:grid-cols-3">
        <SummaryTile label="Feeds" value={data.items.length} hint="configured providers" />
        <SummaryTile label="Enabled" value={enabled} hint="currently refreshing" tone="success" />
        <SummaryTile label="Needs attention" value={errors} hint="last refresh failed" tone={errors ? "danger" : "success"} />
      </div>
      {data.items.map((f) => (
        <FeedRow key={f.feed} feed={f} mutate={(patch) => mut.mutate({ feed: f.feed, patch })} pending={mut.isPending} />
      ))}
    </div>
  );
}

function FeedRow({
  feed,
  mutate,
  pending,
}: {
  feed: FeedDTO;
  mutate: (patch: Record<string, unknown>) => void;
  pending: boolean;
}) {
  const [intervalSec, setIntervalSec] = useState(feed.refresh_seconds);
  const [apiKey, setApiKey] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const status = feed.last_refresh_ok === undefined
    ? "never"
    : feed.last_refresh_ok ? "ok" : "error";
  const statusClasses = status === "ok"
    ? "border-success/50 bg-success/10 text-success"
    : status === "error"
      ? "border-danger/50 bg-danger/10 text-danger"
      : "border-border bg-muted text-subtle";

  return (
    <Card>
      <CardBody>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-lg font-semibold">{feed.feed}</div>
              <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusClasses}`}>
                {status}
              </span>
            </div>
            <div className="mt-0.5 text-xs text-subtle">
              kind: <code>{feed.kind}</code>
              {feed.source_url && <> - source: <code className="break-all">{feed.source_url}</code></>}
            </div>
            <div className="text-xs mt-1 text-subtle">
              {feed.last_refresh_at && (
                <span>Last refresh {new Date(feed.last_refresh_at).toLocaleString()}</span>
              )}
              {!feed.last_refresh_at && <span>Not refreshed yet</span>}
            </div>
            {feed.last_refresh_err && (
              <div className="text-xs text-danger mt-1 break-words" role="alert">{feed.last_refresh_err}</div>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label className="inline-flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={feed.enabled}
                disabled={pending}
                onChange={(e) => {
                  try {
                    mutate({ enabled: e.target.checked });
                  } catch (e) {
                    setErr(e instanceof ApiError ? e.message : String(e));
                  }
                }}
              />
              <span>{feed.enabled ? "Enabled" : "Disabled"}</span>
            </label>
            <HelpTooltip text="Disabled feeds are skipped during refresh and will not add new threat intelligence. Existing cached entries may remain until they expire." />
          </div>
        </div>

        <div className="grid gap-3 grid-cols-1 md:grid-cols-2 mt-3">
          <Field label="Refresh interval (seconds)" hint="30 – 86400" help="How often SentinelMail refreshes this feed. Short intervals update faster but increase external requests and can hit provider limits.">
            <div className="flex gap-2">
              <Input
                type="number"
                min={30}
                max={86_400}
                value={intervalSec}
                onChange={(e) => setIntervalSec(Number(e.target.value))}
              />
              <Button
                variant="secondary"
                disabled={pending || intervalSec === feed.refresh_seconds}
                onClick={() => mutate({ refresh_seconds: intervalSec })}
              >
                Apply
              </Button>
            </div>
          </Field>
          <Field
            label="API key"
            hint={feed.has_api_key ? "key set — leave blank to keep, or enter a new one to replace" : "no key set"}
            help="Optional provider credential for feeds that require authenticated access. Leaving the field blank keeps the existing stored key."
          >
            <div className="flex gap-2">
              <Input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={feed.has_api_key ? "•••••••• (replace)" : "(none)"}
              />
              <Button
                variant="secondary"
                disabled={pending || apiKey === ""}
                onClick={() => {
                  mutate({ api_key: apiKey });
                  setApiKey("");
                }}
              >
                Save
              </Button>
            </div>
          </Field>
        </div>

        {err && <div role="alert" className="text-sm text-danger mt-2">{err}</div>}
      </CardBody>
    </Card>
  );
}

function SummaryTile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number;
  hint: string;
  tone?: "success" | "danger";
}) {
  const toneClass = tone === "success" ? "text-success" : tone === "danger" ? "text-danger" : "text-fg";
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{label}</CardTitle>
      </CardHeader>
      <CardBody>
        <div className={`text-2xl font-semibold tabular-nums ${toneClass}`}>{value.toLocaleString()}</div>
        <div className="text-xs text-subtle">{hint}</div>
      </CardBody>
    </Card>
  );
}
