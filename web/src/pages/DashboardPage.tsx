import { ReactNode, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ChartRow, CompositionDonut, HorizontalBars, StatTile } from "../components/ui/Charts";
import { MailTypeTimeline, TimeTypeRow, TimelineBucketSelection } from "../components/ui/MailTypeTimeline";

interface DailyRow {
  day: string;
  count: number;
}

interface StatsResponse {
  window: string;
  since: string;
  until: string;
  total: number;
  inbound: number;
  outbound: number;
  disposition: ChartRow[];
  delivery_outcomes: ChartRow[];
  threat_categories: ChartRow[];
  email_types: ChartRow[];
  score_bands: ChartRow[];
  phishing_reports: ChartRow[];
  daily_volume: DailyRow[];
  mail_type_timeline: TimeTypeRow[];
  quarantined: number;
  released: number;
  phishing_total: number;
  rejected: number;
  delivered: number;
  tagged: number;
  failed: number;
  blocked_total: number;
}

export function DashboardPage() {
  const [selectedBucket, setSelectedBucket] = useState<TimelineBucketSelection | null>(null);
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard", "summary", "24h"],
    queryFn: () => api.get<StatsResponse>("/reports/summary?window=24h"),
    refetchInterval: 30_000,
  });
  const windowSince = data?.since;
  const windowUntil = data?.until;
  const drilldownHref = (params: Record<string, string | undefined> = {}) => mailLogHref({ since: windowSince, until: windowUntil, ...params });

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">Dashboard</h1>
      <p className="text-sm text-subtle mb-4">
        Activity in the last 24 hours. Click any card to see the matching messages.
      </p>

      {error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Failed to load stats: {error instanceof Error ? error.message : "unknown"}
        </div>
      )}

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total processed" to={drilldownHref()} count={data?.total} isLoading={isLoading} hint="last 24h" />
        <StatCard label="Delivered" to={drilldownHref({ outcome: "delivered" })} count={outcomeCount(data, "delivered")} isLoading={isLoading} tone="success" total={data?.total} hint="share of processed" />
        <StatCard label="Held for review" to={drilldownHref({ outcome: "held_review" })} count={outcomeCount(data, "tagged") + outcomeCount(data, "quarantined")} isLoading={isLoading} tone="warning" total={data?.total} hint="tagged or quarantined" />
        <StatCard label="Blocked, rejected, or failed" to={drilldownHref({ outcome: "blocked_rejected_failed" })} count={(data?.blocked_total ?? 0) + (data?.rejected ?? 0) + (data?.failed ?? 0)} isLoading={isLoading} tone="danger" total={data?.total} hint="blocked or errored" />
      </div>

      <div className="grid gap-4 grid-cols-1 md:grid-cols-3 mt-4">
        <StatCard label="Inbound" to={drilldownHref({ direction: "inbound" })} count={data?.inbound} isLoading={isLoading} tone="accent" total={data?.total} hint="of processed mail" />
        <StatCard label="Outbound" to={drilldownHref({ direction: "outbound" })} count={data?.outbound} isLoading={isLoading} tone="accent" total={data?.total} hint="of processed mail" />
        <StatCard label="Confirmed phishing" to="/reports" count={data?.phishing_total} isLoading={isLoading} tone="danger" total={data?.total} hint="user or scanner confirmed" />
      </div>

      <div className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle>Mail types over time</CardTitle>
          </CardHeader>
          <CardBody>
            <MailTypeTimeline
              rows={data?.mail_type_timeline ?? []}
              empty="No mail type data for the last 24h."
              bucketFormat="hour"
              compact
              selectedBucket={selectedBucket?.key}
              onBucketSelect={setSelectedBucket}
            />
            {selectedBucket && (
              <Link
                to={mailLogHref({ since: selectedBucket.start, until: selectedBucket.end })}
                className="mt-3 inline-flex rounded border border-border px-3 py-2 text-sm hover:bg-muted focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              >
                View {selectedBucket.total.toLocaleString()} matching messages
              </Link>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mt-4">
        <Card>
          <CardHeader>
            <CardTitle>Email types</CardTitle>
          </CardHeader>
          <CardBody>
            <CompositionDonut rows={data?.email_types ?? []} empty="No email type data for the last 24h." label="Email type mix" centerLabel="messages" hrefForRow={(row) => drilldownHref({ email_type: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Threat mix</CardTitle>
          </CardHeader>
          <CardBody>
            <CompositionDonut rows={data?.threat_categories ?? []} empty="No threat data for the last 24h." label="Threat category mix" centerLabel="signals" hrefForRow={(row) => drilldownHref({ threat_category: row.key })} />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mt-4">
        <Card>
          <CardHeader>
            <CardTitle>Score bands</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.score_bands ?? []} empty="No score band data for the last 24h." label="Score bands" hrefForRow={(row) => drilldownHref({ score_band: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Daily volume</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars
              rows={data?.daily_volume.map((r) => ({ key: new Date(r.day).toLocaleDateString(), count: r.count, hrefKey: r.day })) ?? []}
              empty="No daily volume data for the last 24h."
              label="Daily volume"
              maxRows={32}
              showShare={false}
              sort={false}
              hrefForRow={(row) => dayHref(row as ChartRow & { hrefKey?: string }, windowSince, windowUntil)}
            />
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

function mailLogHref(params: Record<string, string | undefined>) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) query.set(key, value);
  }
  const suffix = query.toString();
  return suffix ? `/reports/mail-logs?${suffix}` : "/reports/mail-logs";
}

function dayHref(row: ChartRow & { hrefKey?: string }, minSince?: string, maxUntil?: string) {
  const start = new Date(row.hrefKey ?? row.key);
  if (Number.isNaN(start.getTime())) return "/reports/mail-logs";
  const end = new Date(start);
  end.setDate(end.getDate() + 1);
  const min = minSince ? new Date(minSince) : undefined;
  const max = maxUntil ? new Date(maxUntil) : undefined;
  const boundedStart = min && !Number.isNaN(min.getTime()) && min > start ? min : start;
  const boundedEnd = max && !Number.isNaN(max.getTime()) && max < end ? max : end;
  return mailLogHref({ since: boundedStart.toISOString(), until: boundedEnd.toISOString() });
}

function outcomeCount(data: StatsResponse | undefined, key: string) {
  return data?.delivery_outcomes.find((row) => row.key === key)?.count ?? 0;
}

interface StatCardProps {
  label: string;
  count: number | undefined;
  isLoading: boolean;
  tone?: "success" | "warning" | "danger" | "accent";
  total?: number;
  to: string;
  capitalize?: boolean;
  hint?: ReactNode;
}

function StatCard({ label, count, isLoading, tone, total, to, capitalize, hint }: StatCardProps) {
  // Whole card is a Link so the click target is the visible card, not just
  // a tiny "view" affordance — better for thumbs on touch and faster for
  // mouse users.
  return (
    <Link
      to={to}
      className="block h-full rounded transition-transform hover:-translate-y-0.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
      aria-label={`Show ${label} mail logs`}
    >
      <Card className="flex h-full min-w-0 flex-col hover:border-accent">
        <CardHeader>
          <CardTitle className={capitalize ? "capitalize" : ""}>{label}</CardTitle>
        </CardHeader>
        <CardBody className="flex flex-1">
          <StatTile label={label} value={count} loading={isLoading} tone={tone} total={total} hint={String(hint ?? "last 24h")} showLabel={false} />
        </CardBody>
      </Card>
    </Link>
  );
}
