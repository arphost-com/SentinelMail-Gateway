import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface SentEmail {
  id: string;
  organization_id: string;
  domain_id?: string;
  mail_log_id?: string;
  quarantine_entry_id?: string;
  kind: string;
  from_addr: string;
  to_addrs: string[];
  subject?: string;
  relay_host?: string;
  relay_port?: number;
  status: "pending" | "sent" | "failed";
  error?: string;
  raw_size: number;
  raw_excerpt?: string;
  raw_truncated?: boolean;
  metadata?: Record<string, unknown> | null;
  sent_at?: string;
  created_at: string;
  updated_at: string;
}

const KINDS = [
  "source_ip_abuse_report",
  "phishing_alert",
  "challenge_response_alert",
  "quarantine_release",
  "bulk_quarantine_completion",
  "mailing_list_unsubscribe",
];
const STATUSES = ["pending", "sent", "failed"];

const STATUS_STYLE: Record<string, string> = {
  pending: "border-warning/50 bg-warning/10 text-warning",
  sent: "border-success/50 bg-success/10 text-success",
  failed: "border-danger/50 bg-danger/10 text-danger",
};

export function SentEmailsPage() {
  const qc = useQueryClient();
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [to, setTo] = useState("");
  const [from, setFrom] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(20);
  const [detailID, setDetailID] = useState<string | null>(null);
  const [resendResult, setResendResult] = useState<SentEmail | null>(null);

  const params = new URLSearchParams();
  if (kind) params.set("kind", kind);
  if (status) params.set("status", status);
  if (to.trim()) params.set("to", to.trim());
  if (from.trim()) params.set("from", from.trim());
  if (search.trim()) params.set("q", search.trim());
  params.set("limit", String(limit));
  params.set("offset", String(offset));

  const list = useQuery({
    queryKey: ["sent-emails", kind, status, to, from, search, offset, limit],
    queryFn: () => api.get<ListResponse<SentEmail>>(`/sent-emails?${params.toString()}`),
    refetchInterval: 30_000,
  });

  const detail = useQuery({
    queryKey: ["sent-email", detailID],
    queryFn: () => api.get<SentEmail>(`/sent-emails/${detailID}`),
    enabled: Boolean(detailID),
  });

  const resend = useMutation({
    mutationFn: (id: string) => api.post<SentEmail>(`/sent-emails/${id}/resend`, {}),
    onSuccess: (email) => {
      setResendResult(email);
      setDetailID(email.id);
      qc.invalidateQueries({ queryKey: ["sent-emails"] });
      qc.invalidateQueries({ queryKey: ["sent-email", email.id] });
    },
  });

  function resetPaging(setter: (value: string) => void, value: string) {
    setOffset(0);
    setter(value);
  }

  const columns: ColumnDef<SentEmail>[] = [
    { key: "created", header: "Created", width: 16, sortValue: (email) => email.created_at, render: (email) => new Date(email.created_at).toLocaleString() },
    { key: "kind", header: "Kind", width: 18, sortValue: (email) => email.kind, render: (email) => kindLabel(email.kind) },
    {
      key: "status",
      header: "Status",
      width: 10,
      sortValue: (email) => email.status,
      render: (email) => <StatusBadge status={email.status} />,
    },
    { key: "from", header: "From", width: 18, sortValue: (email) => email.from_addr, render: (email) => <span className="block truncate" title={email.from_addr}>{email.from_addr || "-"}</span> },
    { key: "to", header: "To", width: 20, sortValue: (email) => email.to_addrs.join(","), render: (email) => <span className="block truncate" title={email.to_addrs.join(", ")}>{email.to_addrs.join(", ") || "-"}</span> },
    { key: "subject", header: "Subject", width: 18, sortValue: (email) => email.subject ?? "", render: (email) => <span className="block truncate" title={email.subject ?? "(none)"}>{email.subject || <span className="text-subtle">(none)</span>}</span> },
  ];

  return (
    <div>
      <h1 className="mb-4 text-2xl font-semibold">Sent emails</h1>
      <p className="mb-4 text-sm text-subtle">
        Application-originated email attempts, including abuse reports, user alerts, quarantine releases, and completion notices.
      </p>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-sm">
              <span className="mb-1 block">Kind</span>
              <select
                value={kind}
                onChange={(event) => resetPaging(setKind, event.target.value)}
                className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              >
                <option value="">all</option>
                {KINDS.map((value) => <option key={value} value={value}>{kindLabel(value)}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="mb-1 block">Status</span>
              <select
                value={status}
                onChange={(event) => resetPaging(setStatus, event.target.value)}
                className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              >
                <option value="">all</option>
                {STATUSES.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="mb-1 block">Search</span>
              <Input value={search} onChange={(event) => resetPaging(setSearch, event.target.value)} placeholder="subject, kind, error" />
            </label>
            <label className="text-sm">
              <span className="mb-1 block">Sender contains</span>
              <Input value={from} onChange={(event) => resetPaging(setFrom, event.target.value)} placeholder="no-reply@example.com" />
            </label>
            <label className="text-sm">
              <span className="mb-1 block">Recipient contains</span>
              <Input value={to} onChange={(event) => resetPaging(setTo, event.target.value)} placeholder="abuse@example.net" />
            </label>
          </div>
        </CardBody>
      </Card>

      {list.error && (
        <div role="alert" className="mb-3 text-sm text-danger">
          {list.error instanceof Error ? list.error.message : "Failed to load sent email logs"}
        </div>
      )}
      {resend.error && (
        <div role="alert" className="mb-3 text-sm text-danger">
          Resend failed: {resend.error instanceof Error ? resend.error.message : "unknown"}
        </div>
      )}
      {resendResult && (
        <div role="status" className="mb-3 rounded border border-border bg-muted px-3 py-2 text-sm">
          Resend attempt created for {resendResult.to_addrs.join(", ") || "unknown recipient"} with status <StatusBadge status={resendResult.status} />.
          {resendResult.error && <span className="ml-2 text-danger">{resendResult.error}</span>}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No sent email attempts match the current filters."
        rowKey={(email) => email.id}
        initialSortDirection="desc"
        manualPagination={{
          total: list.data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
        actions={(email) => (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => setDetailID(email.id)}>
              Details
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={resend.isPending || !email.relay_host}
              onClick={() => confirmDanger(`Resend this email to ${email.to_addrs.join(", ")}?`) && resend.mutate(email.id)}
            >
              Resend
            </Button>
          </div>
        )}
      />

      {detailID && (
        <Modal open onClose={() => setDetailID(null)} title="Sent email details" wide>
          {detail.error && (
            <div role="alert" className="mb-3 text-sm text-danger">
              {detail.error instanceof Error ? detail.error.message : "Failed to load sent email"}
            </div>
          )}
          {detail.isLoading && <div className="text-sm text-subtle">Loading...</div>}
          {detail.data && (
            <div className="grid gap-4">
              <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-3">
                <dt className="text-subtle">Created</dt>
                <dd className="break-words md:col-span-2">{new Date(detail.data.created_at).toLocaleString()}</dd>
                <dt className="text-subtle">Status</dt>
                <dd className="md:col-span-2"><StatusBadge status={detail.data.status} /></dd>
                <dt className="text-subtle">Kind</dt>
                <dd className="break-words md:col-span-2">{kindLabel(detail.data.kind)}</dd>
                <dt className="text-subtle">From</dt>
                <dd className="break-all md:col-span-2">{detail.data.from_addr || "-"}</dd>
                <dt className="text-subtle">To</dt>
                <dd className="break-all md:col-span-2">{detail.data.to_addrs.join(", ") || "-"}</dd>
                <dt className="text-subtle">Subject</dt>
                <dd className="break-words md:col-span-2">{detail.data.subject || "-"}</dd>
                <dt className="text-subtle">Relay</dt>
                <dd className="break-words md:col-span-2">{relayLabel(detail.data)}</dd>
                <dt className="text-subtle">Raw size</dt>
                <dd className="break-words md:col-span-2">{formatBytes(detail.data.raw_size)}</dd>
                {detail.data.mail_log_id && (
                  <>
                    <dt className="text-subtle">Mail log</dt>
                    <dd className="break-all md:col-span-2">{detail.data.mail_log_id}</dd>
                  </>
                )}
                {detail.data.quarantine_entry_id && (
                  <>
                    <dt className="text-subtle">Quarantine</dt>
                    <dd className="break-all md:col-span-2">{detail.data.quarantine_entry_id}</dd>
                  </>
                )}
                {detail.data.error && (
                  <>
                    <dt className="text-subtle">Error</dt>
                    <dd className="break-words text-danger md:col-span-2">{detail.data.error}</dd>
                  </>
                )}
              </dl>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="secondary" onClick={() => openRawEmail(detail.data?.id)}>
                  Download raw copy
                </Button>
                <Button
                  size="sm"
                  disabled={resend.isPending || !detail.data.relay_host}
                  onClick={() => confirmDanger(`Resend this email to ${detail.data.to_addrs.join(", ")}?`) && resend.mutate(detail.data.id)}
                >
                  {resend.isPending ? "Resending..." : "Resend"}
                </Button>
              </div>
              <section aria-label="Raw email copy">
                <h2 className="mb-2 text-sm font-semibold">Raw copy</h2>
                {detail.data.raw_truncated && (
                  <p className="mb-2 text-xs text-subtle">Showing the first {formatBytes(detail.data.raw_excerpt?.length ?? 0)}. Download the raw copy for the complete message.</p>
                )}
                <pre className="max-h-[28rem] overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap">
                  {detail.data.raw_excerpt || "No raw copy was available."}
                </pre>
              </section>
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded border px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[status] ?? "border-border bg-muted text-fg"}`}>
      {status}
    </span>
  );
}

function kindLabel(value: string) {
  return value.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function relayLabel(email: SentEmail) {
  if (!email.relay_host) return "-";
  return email.relay_port ? `${email.relay_host}:${email.relay_port}` : email.relay_host;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function openRawEmail(id?: string) {
  if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return;
  window.open(`/api/v1/sent-emails/${id}/raw`, "_blank", "noopener,noreferrer");
}
