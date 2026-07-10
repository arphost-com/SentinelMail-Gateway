import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { HelpTooltip } from "../components/ui/HelpTooltip";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";

interface SmtpEvent {
  id: string;
  queue_id?: string;
  event_type: string;
  phase?: string;
  direction: string;
  from_addr?: string;
  to_addr?: string;
  client_ip?: string;
  helo?: string;
  relay?: string;
  status_code?: string;
  dsn?: string;
  reason?: string;
  raw_log?: string;
  occurred_at: string;
}

const EVENT_TYPES = ["reject", "deferred", "bounced", "failed", "tls_error", "disconnect", "info"];

export function SmtpEventsPage() {
  const [eventType, setEventType] = useState("");
  const [to, setTo] = useState("");
  const [from, setFrom] = useState("");
  const [includeNoise, setIncludeNoise] = useState(false);
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(20);
  const [detail, setDetail] = useState<SmtpEvent | null>(null);

  const params = new URLSearchParams();
  if (eventType) params.set("event_type", eventType);
  if (to) params.set("to", to);
  if (from) params.set("from", from);
  if (includeNoise) params.set("include_noise", "true");
  params.set("limit", String(limit));
  params.set("offset", String(offset));

  const list = useQuery({
    queryKey: ["smtp-events", eventType, to, from, includeNoise, offset, limit],
    queryFn: () => api.get<ListResponse<SmtpEvent>>(`/smtp-events?${params.toString()}`),
    refetchInterval: 30_000,
  });

  const columns: ColumnDef<SmtpEvent>[] = [
    { key: "time", header: "Time", width: 15, sortValue: (e) => e.occurred_at, render: (e) => new Date(e.occurred_at).toLocaleString() },
    { key: "type", header: "Type", width: 10, sortValue: (e) => e.event_type, render: (e) => <span className="rounded bg-muted px-2 py-0.5 text-xs">{e.event_type}</span> },
    { key: "from", header: "From", width: 17, sortValue: (e) => e.from_addr ?? "", render: (e) => <span title={e.from_addr}>{e.from_addr ?? "-"}</span> },
    { key: "to", header: "To", width: 17, sortValue: (e) => e.to_addr ?? "", render: (e) => <span title={e.to_addr}>{e.to_addr ?? "-"}</span> },
    { key: "client", header: "Client", width: 10, sortValue: (e) => e.client_ip ?? "", render: (e) => <span className="font-mono text-xs">{e.client_ip ?? "-"}</span> },
    { key: "status", header: "Status", width: 10, sortValue: (e) => e.status_code ?? e.dsn ?? "", render: (e) => e.status_code ?? e.dsn ?? "-" },
    { key: "reason", header: "Reason", width: 21, sortValue: (e) => e.reason ?? "", render: (e) => <span title={e.reason}>{e.reason ?? "-"}</span> },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">SMTP events</h1>
      <p className="mb-4 text-sm text-subtle">
        Postfix-only SMTP attempts, rejects, TLS failures, and delivery deferrals that may happen before accepted mail reaches the normal mail log.
      </p>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="grid gap-3 grid-cols-1 md:grid-cols-4">
            <label className="text-sm">
              <span className="block mb-1">Type</span>
              <select
                value={eventType}
                onChange={(event) => {
                  setOffset(0);
                  setEventType(event.target.value);
                }}
                className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              >
                <option value="">all</option>
                {EVENT_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="block mb-1">Recipient contains</span>
              <Input
                value={to}
                onChange={(event) => {
                  setOffset(0);
                  setTo(event.target.value);
                }}
                placeholder="larkin@example.com"
              />
            </label>
            <label className="text-sm">
              <span className="block mb-1">Sender contains</span>
              <Input
                value={from}
                onChange={(event) => {
                  setOffset(0);
                  setFrom(event.target.value);
                }}
                placeholder="sender@example.com"
              />
            </label>
            <label className="flex items-center gap-2 self-end rounded border border-border bg-surface px-3 py-2 text-sm">
              <input
                type="checkbox"
                checked={includeNoise}
                onChange={(event) => {
                  setOffset(0);
                  setIncludeNoise(event.target.checked);
                }}
              />
              <span>Show suppressed queue noise</span>
              <HelpTooltip text="When off, deferred, bounced, and failed events tied to system, organization, or domain blocklisted senders are hidden from the default view." />
            </label>
          </div>
        </CardBody>
      </Card>

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {list.error instanceof Error ? list.error.message : "Failed to load SMTP events"}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No SMTP events match the current filters."
        rowKey={(event) => event.id}
        initialSortDirection="desc"
        manualPagination={{
          total: list.data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
        actions={(event) => (
          <Button size="sm" variant="secondary" onClick={() => setDetail(event)}>
            Details
          </Button>
        )}
      />

      {detail && (
        <Modal open onClose={() => setDetail(null)} title={`${detail.event_type} event`} wide>
          <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-3">
            <dt className="text-subtle">Time</dt>
            <dd className="break-words md:col-span-2">{new Date(detail.occurred_at).toLocaleString()}</dd>
            <dt className="text-subtle">Queue ID</dt>
            <dd className="break-words md:col-span-2">{detail.queue_id ?? "-"}</dd>
            <dt className="text-subtle">From</dt>
            <dd className="break-all md:col-span-2">{detail.from_addr ?? "-"}</dd>
            <dt className="text-subtle">To</dt>
            <dd className="break-all md:col-span-2">{detail.to_addr ?? "-"}</dd>
            <dt className="text-subtle">Client</dt>
            <dd className="break-words md:col-span-2">{detail.client_ip ?? "-"}</dd>
            <dt className="text-subtle">Relay</dt>
            <dd className="break-words md:col-span-2">{detail.relay ?? "-"}</dd>
            <dt className="text-subtle">Reason</dt>
            <dd className="break-words md:col-span-2">{detail.reason ?? "-"}</dd>
            <dt className="text-subtle">Raw log</dt>
            <dd className="rounded bg-muted p-3 font-mono text-xs break-words md:col-span-2">{detail.raw_log ?? "-"}</dd>
          </dl>
        </Modal>
      )}
    </div>
  );
}
