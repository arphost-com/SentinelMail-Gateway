import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Modal } from "../components/ui/Modal";
import { ScamGuidance } from "../components/ui/ScamGuidance";
import { confirmDanger } from "../components/ui/confirm";

interface MailLog {
  id: string;
  organization_id: string;
  domain_id?: string;
  queue_id?: string;
  message_id?: string;
  direction: string;
  from_addr?: string;
  to_addrs: string[];
  client_ip?: string;
  helo?: string;
  subject?: string;
  size_bytes?: number;
  rspamd_score?: number;
  rspamd_action?: string;
  symbols?: Record<string, unknown> | null;
  disposition: string;
  reason?: string;
  email_type: string;
  scam_warning?: string;
  scam_signals?: string[];
  scam_links?: Array<{ label: string; url: string }>;
  received_at: string;
}

interface MailLogActionResponse {
  message: string;
  pattern?: string;
  scope?: string;
  released?: number;
  deleted?: number;
  failed?: number;
  sent?: boolean;
  sent_to?: string[];
  warning?: string;
  report_ip?: string;
  report_body?: string;
  can_send?: boolean;
}

const DELIVERY_OUTCOMES = ["delivered", "tagged", "quarantined", "blocked", "rejected", "deferred", "failed"];
const DIRECTIONS = ["inbound", "outbound"];

const OUTCOME_STYLE: Record<string, string> = {
  delivered:   "border-success/50 bg-success/10 text-success",
  tagged:      "border-warning/50 bg-warning/10 text-warning",
  quarantined: "border-warning/50 bg-warning/10 text-warning",
  blocked:     "border-danger/50 bg-danger/10 text-danger",
  rejected:    "border-danger/50 bg-danger/10 text-danger",
  deferred:    "border-border bg-muted text-fg",
  failed:      "border-danger/50 bg-danger/10 text-danger",
};

function deliveryOutcome(log: MailLog) {
  return log.reason?.toLowerCase() === "sender matched blacklist" ? "blocked" : log.disposition;
}

export function MailLogsPage() {
  const qc = useQueryClient();
  // Filter state is mirrored in the URL so deep links (and the Dashboard
  // click-through) work — `/reports/mail-logs?outcome=quarantined` lands here
  // with the filter pre-applied.
  const [params, setParams] = useSearchParams();
  const outcome = params.get("outcome") ?? params.get("disposition") ?? "";
  const direction = params.get("direction") ?? "";
  const search = params.get("q") ?? "";
  const drilldownFilters = ["since", "until", "from", "to", "sender_domain", "domain", "symbol", "score_band", "email_type", "threat_category", "reason"]
    .map((key) => [key, params.get(key) ?? ""] as const)
    .filter(([, value]) => value);
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(10);

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key === "outcome") next.delete("disposition");
    setParams(next, { replace: true });
    setOffset(0);
  }

  const query = new URLSearchParams();
  if (outcome) query.set("outcome", outcome);
  if (direction) query.set("direction", direction);
  if (search) query.set("q", search);
  for (const [key, value] of drilldownFilters) {
    query.set(key, value);
  }
  query.set("limit", String(limit));
  query.set("offset", String(offset));

  const list = useQuery({
    queryKey: ["mail-logs", outcome, direction, search, drilldownFilters, offset, limit],
    queryFn: () => api.get<ListResponse<MailLog>>(`/mail-logs?${query.toString()}`),
    refetchInterval: 15_000,
  });

  const [detail, setDetail] = useState<MailLog | null>(null);
  const [actionResult, setActionResult] = useState<MailLogActionResponse | null>(null);

  const runAction = useMutation({
    mutationFn: ({ id, action, body }: { id: string; action: string; body?: Record<string, string> }) =>
      api.post<MailLogActionResponse>(`/mail-logs/${id}/${action}`, body ?? {}),
    onSuccess: (result) => {
      setActionResult(result);
      qc.invalidateQueries({ queryKey: ["mail-logs"] });
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
    },
  });

  const cols: ColumnDef<MailLog>[] = [
    {
      key: "when",
      header: "Received",
      className: "whitespace-nowrap",
      sortValue: (l) => l.received_at,
      render: (l) => new Date(l.received_at).toLocaleString(),
    },
    {
      key: "dir",
      header: "Direction",
      sortValue: (l) => l.direction,
      render: (l) => <span className="text-xs text-subtle">{l.direction}</span>,
    },
    { key: "from", header: "From", className: "max-w-[14rem] truncate", sortValue: (l) => l.from_addr ?? "", render: (l) => l.from_addr ?? "—" },
    { key: "subj", header: "Subject", className: "max-w-[20rem] truncate", sortValue: (l) => l.subject ?? "", render: (l) => l.subject ?? <span className="text-subtle">(none)</span> },
    {
      key: "score",
      header: "Score",
      className: "text-right tabular-nums",
      sortValue: (l) => l.rspamd_score,
      render: (l) => l.rspamd_score?.toFixed(1) ?? "—",
    },
    {
      key: "disp",
      header: "Delivery outcome",
      sortValue: (l) => deliveryOutcome(l),
      render: (l) => (
        <span className={`rounded border px-2 py-0.5 text-xs font-medium ${OUTCOME_STYLE[deliveryOutcome(l)] ?? "border-border bg-muted"}`}>
          {deliveryOutcome(l)}
        </span>
      ),
    },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Mail logs</h1>
      </div>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Field label="Search logs">
            <input
              value={search}
              onChange={(e) => setParam("q", e.target.value)}
              placeholder="sender, recipient, subject, queue, reason"
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg placeholder:text-subtle"
            />
          </Field>
          <Field label="Delivery outcome">
            <select
              value={outcome}
              onChange={(e) => setParam("outcome", e.target.value)}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">all</option>
              {DELIVERY_OUTCOMES.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </Field>
          <Field label="Direction">
            <select
              value={direction}
              onChange={(e) => setParam("direction", e.target.value)}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">all</option>
              {DIRECTIONS.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </Field>
        </CardBody>
      </Card>

      {drilldownFilters.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded border border-border bg-muted/30 px-3 py-2 text-sm">
          <span className="text-subtle">Drilldown</span>
          {drilldownFilters.map(([key, value]) => (
            <span key={key} className="rounded bg-surface px-2 py-1">
              {filterLabel(key)}: <span className="font-medium">{formatFilterValue(key, value)}</span>
            </span>
          ))}
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              const next = new URLSearchParams(params);
              for (const [key] of drilldownFilters) next.delete(key);
              setParams(next, { replace: true });
              setOffset(0);
            }}
          >
            Clear drilldown
          </Button>
        </div>
      )}

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {list.error instanceof Error ? list.error.message : "Failed to load"}
        </div>
      )}

      <DataTable
        columns={cols}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No mail processed yet that matches the current filters."
        rowKey={(l) => l.id}
        initialSortDirection="desc"
        manualPagination={{
          total: list.data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
        actions={(l) => (
          <Button size="sm" variant="secondary" onClick={() => { setDetail(l); setActionResult(null); runAction.reset(); }}>Details</Button>
        )}
      />

      {detail && (
        <Modal open onClose={() => { setDetail(null); setActionResult(null); runAction.reset(); }} title={`Mail log ${detail.id.slice(0, 8)}`} wide>
          <dl className="grid grid-cols-3 gap-2 text-sm mb-3">
            <dt className="text-subtle">Received</dt>
            <dd className="col-span-2">{new Date(detail.received_at).toLocaleString()}</dd>
            <dt className="text-subtle">Direction</dt>
            <dd className="col-span-2">{detail.direction}</dd>
            <dt className="text-subtle">Delivery outcome</dt>
            <dd className="col-span-2">
              <span className={`rounded border px-2 py-0.5 text-xs font-medium ${OUTCOME_STYLE[deliveryOutcome(detail)] ?? "border-border bg-muted"}`}>
                {deliveryOutcome(detail)}
              </span>
              {detail.reason && <span className="ml-2 text-subtle">— {detail.reason}</span>}
            </dd>
            <dt className="text-subtle">From</dt>
            <dd className="col-span-2 break-all">{detail.from_addr ?? "—"}</dd>
            <dt className="text-subtle">To</dt>
            <dd className="col-span-2 break-all">{detail.to_addrs?.join(", ") ?? "—"}</dd>
            <dt className="text-subtle">Subject</dt>
            <dd className="col-span-2 break-words">{detail.subject ?? <span className="text-subtle">(none)</span>}</dd>
            <dt className="text-subtle">Type</dt>
            <dd className="col-span-2">{detail.email_type}</dd>
            <dt className="text-subtle">Client IP</dt>
            <dd className="col-span-2 font-mono text-xs">{detail.client_ip ?? "—"}</dd>
            <dt className="text-subtle">HELO</dt>
            <dd className="col-span-2 font-mono text-xs">{detail.helo ?? "—"}</dd>
            <dt className="text-subtle">Message-ID</dt>
            <dd className="col-span-2 font-mono text-xs break-all">{detail.message_id ?? "—"}</dd>
            <dt className="text-subtle">Queue ID</dt>
            <dd className="col-span-2 font-mono text-xs">{detail.queue_id ?? "—"}</dd>
            <dt className="text-subtle">Size</dt>
            <dd className="col-span-2 tabular-nums">{detail.size_bytes ?? 0} bytes</dd>
            <dt className="text-subtle">Rspamd</dt>
            <dd className="col-span-2">
              score <span className="font-mono">{detail.rspamd_score ?? "—"}</span>
              {detail.rspamd_action && (
                <> · action <span className="font-mono">{detail.rspamd_action}</span></>
              )}
            </dd>
          </dl>
          <div className="mb-3">
            <ScamGuidance item={detail} />
          </div>
          <div className="mb-3 flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={!detail.client_ip || runAction.isPending}
              onClick={() => confirmDanger("Send a source IP abuse report for this mail log?") && runAction.mutate({ id: detail.id, action: "source-ip-report" })}
            >
              Report source IP
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!detail.from_addr || runAction.isPending}
              onClick={() => runAction.mutate({ id: detail.id, action: "block-sender", body: { match: "sender" } })}
            >
              Block sender
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!detail.from_addr || runAction.isPending}
              onClick={() => runAction.mutate({ id: detail.id, action: "block-sender", body: { match: "domain" } })}
            >
              Block sender domain
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!detail.from_addr || runAction.isPending}
              onClick={() => runAction.mutate({ id: detail.id, action: "block-sender", body: { match: "root_domain" } })}
            >
              Block root domain
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!detail.from_addr || runAction.isPending}
              onClick={() => runAction.mutate({ id: detail.id, action: "not-spam" })}
            >
              Mark not spam
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={runAction.isPending}
              onClick={() => runAction.mutate({ id: detail.id, action: "release" })}
            >
              Release
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={runAction.isPending}
              onClick={() => confirmDanger("Delete held quarantine copies for this mail log?") && runAction.mutate({ id: detail.id, action: "delete-held" })}
            >
              Delete
            </Button>
          </div>
          {runAction.error && (
            <div role="alert" className="mb-3 text-sm text-danger">
              Action failed: {runAction.error instanceof Error ? runAction.error.message : "unknown"}
            </div>
          )}
          {actionResult && (
            <div role="status" className="mb-3 rounded border border-border bg-muted px-3 py-2 text-sm">
              <div>{actionResult.message}</div>
              {actionResult.pattern && <div>Pattern: <span className="font-mono">{actionResult.pattern}</span>{actionResult.scope ? ` (${actionResult.scope})` : ""}</div>}
              {(actionResult.released !== undefined || actionResult.deleted !== undefined || actionResult.failed !== undefined) && (
                <div>
                  {actionResult.released !== undefined ? `Released: ${actionResult.released}. ` : ""}
                  {actionResult.deleted !== undefined ? `Deleted: ${actionResult.deleted}. ` : ""}
                  {actionResult.failed !== undefined ? `Failed: ${actionResult.failed}.` : ""}
                </div>
              )}
              {actionResult.sent_to && actionResult.sent_to.length > 0 && <div>Sent to: {actionResult.sent_to.join(", ")}</div>}
              {actionResult.warning && <div className="text-warning">{actionResult.warning}</div>}
              {actionResult.report_body && <pre className="mt-2 max-h-48 overflow-auto rounded bg-surface p-2 text-xs whitespace-pre-wrap">{actionResult.report_body}</pre>}
            </div>
          )}
          <h3 className="text-sm font-semibold mb-1">Symbols</h3>
          <pre className="text-xs bg-muted p-3 rounded overflow-auto max-h-64">
            {JSON.stringify(detail.symbols ?? {}, null, 2)}
          </pre>
        </Modal>
      )}
    </div>
  );
}

function filterLabel(key: string) {
  switch (key) {
    case "score_band":
      return "score";
    case "email_type":
      return "email type";
    case "threat_category":
      return "threat category";
    case "from":
      return "sender";
    case "to":
      return "recipient";
    default:
      return key.replace("_", " ");
  }
}

function formatFilterValue(key: string, value: string) {
  if (key === "since" || key === "until") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString();
  }
  return value;
}
