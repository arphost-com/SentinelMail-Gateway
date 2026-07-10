import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, ListResponse } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ChartRow, CompositionDonut, HorizontalBars, StatTile } from "../components/ui/Charts";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { MailTypeTimeline, TimeTypeRow, TimelineBucketSelection } from "../components/ui/MailTypeTimeline";

interface DailyRow {
  day: string;
  count: number;
}

interface ReportsSummary {
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
  top_symbols: ChartRow[];
  top_domains: ChartRow[];
  top_senders: ChartRow[];
  blocked_senders: ChartRow[];
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

interface PhishingReport {
  id: string;
  domain: string;
  mail_log_id?: string;
  source: string;
  status: string;
  phishing_type: string;
  verdict: string;
  from_addr: string;
  to_addr: string;
  subject: string;
  evidence: Record<string, unknown>;
  reported_at: string;
}

const WINDOWS = [
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
];

export function ReportsPage() {
  const [windowValue, setWindowValue] = useState("7d");
  const [phishingOffset, setPhishingOffset] = useState(0);
  const [phishingLimit, setPhishingLimit] = useState(10);
  const [selectedBucket, setSelectedBucket] = useState<TimelineBucketSelection | null>(null);
  const report = useQuery({
    queryKey: ["reports", "summary", windowValue],
    queryFn: () => api.get<ReportsSummary>(`/reports/summary?window=${windowValue}`),
    refetchInterval: 60_000,
  });
  const phishing = useQuery({
    queryKey: ["reports", "phishing", windowValue, phishingOffset, phishingLimit],
    queryFn: () => api.get<ListResponse<PhishingReport>>(`/reports/phishing?window=${windowValue}&limit=${phishingLimit}&offset=${phishingOffset}`),
    refetchInterval: 60_000,
  });
  const data = report.data;
  const windowSince = data?.since;
  const windowUntil = data?.until;
  const drilldownHref = (params: Record<string, string | undefined> = {}) => mailLogHref({ since: windowSince, until: windowUntil, ...params });

  const phishingColumns: ColumnDef<PhishingReport>[] = [
    { key: "reported", header: "Reported", className: "whitespace-nowrap", sortValue: (r) => r.reported_at, render: (r) => new Date(r.reported_at).toLocaleString() },
    { key: "type", header: "Type", sortValue: (r) => r.phishing_type, render: (r) => <span className="rounded bg-muted px-2 py-0.5 text-xs">{r.phishing_type}</span> },
    { key: "source", header: "Source", sortValue: (r) => r.source, render: (r) => <span className="capitalize">{r.source.replace("_", " ")}</span> },
    { key: "status", header: "Status", sortValue: (r) => r.status, render: (r) => <span className="capitalize">{r.status.replace("_", " ")}</span> },
    { key: "domain", header: "Domain", className: "max-w-[12rem] truncate", render: (r) => r.domain || "—" },
    { key: "from", header: "From", className: "max-w-[14rem] truncate", sortValue: (r) => r.from_addr, render: (r) => r.from_addr || "—" },
    { key: "to", header: "To", className: "max-w-[14rem] truncate", sortValue: (r) => r.to_addr, render: (r) => r.to_addr || "—" },
    { key: "subject", header: "Subject", className: "max-w-[22rem] truncate", sortValue: (r) => r.subject, render: (r) => r.subject || <span className="text-subtle">(none)</span> },
  ];

  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold mb-1">Reports</h1>
          <p className="text-sm text-subtle">Message volume, enforcement outcomes, and spam signals.</p>
        </div>
        <label className="text-sm">
          <span className="block text-subtle mb-1">Window</span>
          <select
            value={windowValue}
            onChange={(e) => {
              setWindowValue(e.target.value);
              setPhishingOffset(0);
            }}
            className="block rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            {WINDOWS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
          </select>
        </label>
      </div>

      {report.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          {report.error instanceof Error ? report.error.message : "Failed to load reports"}
        </div>
      )}

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-4 mb-4">
        <Metric label="Processed" to={drilldownHref()} value={data?.total} loading={report.isLoading} hint={windowLabel(windowValue)} />
        <Metric label="Delivered" to={drilldownHref({ outcome: "delivered" })} value={outcomeCount(data, "delivered")} loading={report.isLoading} tone="success" total={data?.total} hint="share of processed" />
        <Metric label="Held for review" to={drilldownHref({ outcome: "held_review" })} value={outcomeCount(data, "tagged") + outcomeCount(data, "quarantined")} loading={report.isLoading} tone="warning" total={data?.total} hint="tagged or quarantined" />
        <Metric label="Blocked, rejected, or failed" to={drilldownHref({ outcome: "blocked_rejected_failed" })} value={(data?.blocked_total ?? 0) + (data?.rejected ?? 0) + (data?.failed ?? 0)} loading={report.isLoading} tone="danger" total={data?.total} hint="blocked or errored" />
      </div>

      <div className="grid gap-4 grid-cols-1 md:grid-cols-4 mb-4">
        <Metric label="Inbound" to={drilldownHref({ direction: "inbound" })} value={data?.inbound} loading={report.isLoading} tone="accent" total={data?.total} hint="of processed mail" />
        <Metric label="Outbound" to={drilldownHref({ direction: "outbound" })} value={data?.outbound} loading={report.isLoading} tone="accent" total={data?.total} hint="of processed mail" />
        <Metric label="Sender blocklist" to={drilldownHref({ reason: "sender matched blacklist" })} value={data?.blocked_total} loading={report.isLoading} tone="danger" total={data?.total} hint="blocked by allow/block list" />
        <Metric label="Confirmed phishing" to="#phishing-reports" value={data?.phishing_total} loading={report.isLoading} tone="danger" total={data?.total} hint="user or scanner confirmed" />
      </div>

      <div className="mb-4">
        <Card>
          <CardHeader>
            <CardTitle>Mail types over time</CardTitle>
          </CardHeader>
          <CardBody>
            <MailTypeTimeline
              rows={data?.mail_type_timeline ?? []}
              bucketFormat={windowValue === "24h" ? "hour" : "day"}
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

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mb-4">
        <Card>
          <CardHeader>
            <CardTitle>Threat mix</CardTitle>
          </CardHeader>
          <CardBody>
            <CompositionDonut rows={data?.threat_categories ?? []} empty="No threat data for this window." label="Threat category mix" centerLabel="signals" hrefForRow={(row) => drilldownHref({ threat_category: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Email types</CardTitle>
          </CardHeader>
          <CardBody>
            <CompositionDonut rows={data?.email_types ?? []} empty="No email type data for this window." label="Email type mix" centerLabel="messages" hrefForRow={(row) => drilldownHref({ email_type: row.key })} />
          </CardBody>
        </Card>
      </div>

      <Card className="mb-4" id="phishing-reports">
        <CardHeader>
          <CardTitle>Phishing reports</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          {phishing.error && (
            <div role="alert" className="p-4 text-sm text-danger">
              {phishing.error instanceof Error ? phishing.error.message : "Failed to load phishing reports"}
            </div>
          )}
          <DataTable
            columns={phishingColumns}
            rows={phishing.data?.items}
            loading={phishing.isLoading}
            empty="No phishing reports for this window."
            rowKey={(row) => row.id}
            initialSortDirection="desc"
            manualPagination={{
              total: phishing.data?.total ?? 0,
              offset: phishingOffset,
              pageSize: phishingLimit,
              onOffsetChange: setPhishingOffset,
              onPageSizeChange: setPhishingLimit,
            }}
          />
        </CardBody>
      </Card>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mb-4">
        <Card>
          <CardHeader>
            <CardTitle>Score bands</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.score_bands ?? []} empty="No score band data for this window." label="Score bands" hrefForRow={(row) => drilldownHref({ score_band: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Phishing confirmations</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.phishing_reports ?? []} empty="No phishing confirmation data for this window." label="Phishing confirmations" capitalize hrefForRow={() => "#phishing-reports"} />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mb-4">
        <Card>
          <CardHeader>
            <CardTitle>Daily volume</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars
              rows={data?.daily_volume.map((r) => ({ key: new Date(r.day).toLocaleDateString(), count: r.count, hrefKey: r.day })) ?? []}
              empty="No daily volume data for this window."
              label="Daily volume"
              maxRows={32}
              showShare={false}
              sort={false}
              hrefForRow={(row) => dayHref(row as ChartRow & { hrefKey?: string }, windowSince, windowUntil)}
            />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Delivery outcome</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.delivery_outcomes ?? []} empty="No delivery outcome data for this window." label="Delivery outcome" capitalize hrefForRow={(row) => drilldownHref({ outcome: row.key })} />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Top domains</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.top_domains ?? []} empty="No domain data for this window." label="Top domains" monospace hrefForRow={(row) => drilldownHref({ domain: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Top Rspamd symbols</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.top_symbols ?? []} empty="No Rspamd symbol data for this window." label="Top Rspamd symbols" monospace hrefForRow={(row) => drilldownHref({ symbol: row.key })} />
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-2 mt-4">
        <Card>
          <CardHeader>
            <CardTitle>Top senders</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.top_senders ?? []} empty="No sender data for this window." label="Top senders" monospace hrefForRow={(row) => drilldownHref({ from: row.key })} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Blocked sender domains</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={data?.blocked_senders ?? []} empty="No sender blocklist hits for this window." label="Blocked sender domains" monospace hrefForRow={(row) => drilldownHref({ sender_domain: row.key, reason: "sender matched blacklist" })} />
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  loading,
  tone,
  total,
  hint,
  to,
}: {
  label: string;
  value: number | undefined;
  loading: boolean;
  tone?: "success" | "warning" | "danger" | "accent";
  total?: number;
  hint: string;
  to?: string;
}) {
  const body = (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
      </CardHeader>
      <CardBody>
        <StatTile label={label} value={value} loading={loading} tone={tone} total={total} hint={hint} showLabel={false} />
      </CardBody>
    </Card>
  );
  if (!to) return body;
  return (
    <Link to={to} className="block rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focus">
      {body}
    </Link>
  );
}

function windowLabel(value: string) {
  return WINDOWS.find((windowOption) => windowOption.value === value)?.label ?? value;
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

function outcomeCount(data: ReportsSummary | undefined, key: string) {
  return data?.delivery_outcomes.find((row) => row.key === key)?.count ?? 0;
}
