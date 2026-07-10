import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ListResponse } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { isAdmin } from "../auth/roles";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { ScamGuidance } from "../components/ui/ScamGuidance";
import { SpoofWarning } from "../components/ui/SpoofWarning";

interface QuarantineEntry {
  id: string;
  organization_id: string;
  from_addr?: string;
  to_addr: string;
  subject?: string;
  rspamd_score?: number;
  threat_class?: string;
  client_ip?: string;
  state: string;
  size_bytes?: number;
  has_blob: boolean;
  can_release: boolean;
  email_type: string;
  scam_warning?: string;
  scam_signals?: string[];
  scam_links?: Array<{ label: string; url: string }>;
  auth_status?: string;
  spoof_warning?: string;
  spoof_signals?: string[];
  headers?: Array<{ name: string; value: string }>;
  content_text?: string;
  raw_excerpt?: string;
  expires_at?: string;
  received_at: string;
  released_at?: string;
}

interface SourceIPReport {
  ip: string;
  network_name?: string;
  abuse_contacts: string[];
  report_subject: string;
  report_body: string;
  can_send: boolean;
  sent?: boolean;
  sent_to?: string[];
  warning?: string;
  outbound_server?: string;
  submission_mode?: "email" | "webform";
  webform?: SourceIPWebform;
}

interface SourceIPWebform {
  provider: string;
  url: string;
  abuse_type: string;
  abuse_subtype?: string;
  reported_ip: string;
  date_of_incident: string;
  additional_information: string;
  attachment_note?: string;
  contact_name?: string;
  contact_email?: string;
  company_name?: string;
  phone_number?: string;
  privacy_confirmation?: string;
  accuracy_confirmation?: string;
}

interface BlockSenderResponse {
  pattern: string;
  scope: string;
  existing: boolean;
  message: string;
}

interface PurgeExpiredResponse {
  purged_entries: number;
  purged_blobs: number;
}

interface BulkActionResponse {
  action: string;
  queued: boolean;
  requested: number;
  processed: number;
  succeeded: number;
  failed: number;
  email_sent_to?: string[];
  message: string;
  notify_to?: string;
  notification_preference?: "email" | "in_app" | "both" | "off";
}

type DetailTab = "summary" | "analysis" | "headers" | "content";
type QuarantineVerdict = "spam" | "phishing" | "malware" | "other";
type DisplayVerdict = QuarantineVerdict | "not_spam";
type BlockMatch = "sender" | "domain" | "root_domain";
type BulkAction = "release" | "delete" | "block_sender" | "block_domain" | "block_root_domain" | "report_source_ip" | "mark_spam" | "mark_phishing" | "mark_malware" | "mark_other";

interface BlockDialogState {
  id: string;
  match: Extract<BlockMatch, "domain" | "root_domain">;
  sender: string;
  pattern: string;
  verdict: QuarantineVerdict;
}

const QUARANTINE_VERDICTS: Array<{ value: QuarantineVerdict; label: string }> = [
  { value: "spam", label: "Spam" },
  { value: "phishing", label: "Phishing" },
  { value: "malware", label: "Malware" },
  { value: "other", label: "Other" },
];

export function QuarantinePage() {
  const qc = useQueryClient();
  const { me } = useAuth();
  const [urlParams, setUrlParams] = useSearchParams();
  const canPurgeExpired = isAdmin(me?.role);
  const [state, setState] = useState<string>("held");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [detailPreview, setDetailPreview] = useState<QuarantineEntry | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTab>("summary");
  const [sourceIPReport, setSourceIPReport] = useState<SourceIPReport | null>(null);
  const [sourceIPReportEntry, setSourceIPReportEntry] = useState<QuarantineEntry | null>(null);
  const [blockSenderResult, setBlockSenderResult] = useState<BlockSenderResponse | null>(null);
  const [purgeResult, setPurgeResult] = useState<PurgeExpiredResponse | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkActionResponse | null>(null);
  const [blockDialog, setBlockDialog] = useState<BlockDialogState | null>(null);
  const [limit, setLimit] = useState(10);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const linkedQuarantineID = urlParams.get("id");

  const params = new URLSearchParams();
  if (state) params.set("state", state);
  if (search) params.set("search", search);
  params.set("limit", String(limit));
  params.set("offset", String(offset));

  const { data, isLoading, error } = useQuery({
    queryKey: ["quarantine", state, search, offset, limit],
    queryFn: () => api.get<ListResponse<QuarantineEntry>>(`/quarantine?${params.toString()}`),
  });
  const detail = useQuery({
    queryKey: ["quarantine", detailPreview?.id],
    queryFn: () => api.get<QuarantineEntry>(`/quarantine/${detailPreview?.id}`),
    enabled: Boolean(detailPreview?.id),
  });
  const detailItem = detail.data ?? detailPreview;
  const detailIsChallenge = detailItem ? isChallengeResponseEntry(detailItem) : false;

  const release = useMutation({
    mutationFn: (id: string) => api.post(`/quarantine/${id}/release`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      closeDetail();
    },
  });

  const notSpam = useMutation({
    mutationFn: (id: string) => api.post<BlockSenderResponse>(`/quarantine/${id}/not-spam`),
    onSuccess: (result) => {
      setBlockSenderResult(result);
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
      closeDetail();
    },
  });

  const del = useMutation({
    mutationFn: (id: string) => api.del(`/quarantine/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      closeDetail();
    },
  });

  const prepareSourceIPReport = useMutation({
    mutationFn: (id: string) => api.get<SourceIPReport>(`/quarantine/${id}/source-ip-report`),
    onSuccess: (report) => setSourceIPReport(report),
  });

  const sendSourceIPReport = useMutation({
    mutationFn: (id: string) => api.post<SourceIPReport>(`/quarantine/${id}/source-ip-report`),
    onSuccess: (report) => setSourceIPReport(report),
  });

  const blockSender = useMutation({
    mutationFn: ({ id, match, verdict, pattern }: { id: string; match: BlockMatch; verdict: QuarantineVerdict; pattern?: string }) =>
      api.post<BlockSenderResponse>(`/quarantine/${id}/block-sender`, pattern ? { match, verdict, pattern } : { match, verdict }),
    onSuccess: (result) => {
      setBlockSenderResult(result);
      setBlockDialog(null);
      qc.invalidateQueries({ queryKey: ["quarantine"] });
    },
  });

  const allowSender = useMutation({
    mutationFn: ({ id, match }: { id: string; match: "domain" | "root_domain" }) =>
      api.post<BlockSenderResponse>(`/quarantine/${id}/allow-sender`, { match }),
    onSuccess: (result) => {
      setBlockSenderResult(result);
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
      setDetailPreview((current) => current ? { ...current, threat_class: "NOT_SPAM", email_type: "not spam" } : current);
    },
  });

  const setQuarantineVerdict = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: QuarantineVerdict }) =>
      api.post<BlockSenderResponse>(`/quarantine/${id}/verdict`, { verdict }),
    onSuccess: (result) => {
      setBlockSenderResult(result);
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      closeDetail();
    },
  });

  const purgeExpired = useMutation({
    mutationFn: () => api.post<PurgeExpiredResponse>("/quarantine/purge-expired"),
    onSuccess: (result) => {
      setPurgeResult(result);
      qc.invalidateQueries({ queryKey: ["quarantine"] });
    },
  });

  const bulk = useMutation({
    mutationFn: ({ action }: { action: BulkAction }) =>
      api.post<BulkActionResponse>("/quarantine/bulk", { ids: Array.from(selected), action }),
    onSuccess: (result) => {
      setBulkResult(result);
      setSelected(new Set());
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      closeDetail();
    },
  });

  const visibleIDs = useMemo(() => data?.items.map((entry) => entry.id) ?? [], [data?.items]);
  const selectedCount = selected.size;
  const allVisibleSelected = visibleIDs.length > 0 && visibleIDs.every((id) => selected.has(id));

  useEffect(() => {
    setSelected((current) => {
      const visible = new Set(visibleIDs);
      const next = new Set(Array.from(current).filter((id) => visible.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [visibleIDs]);

  useEffect(() => {
    if (!linkedQuarantineID || detailPreview?.id === linkedQuarantineID) return;
    setDetailPreview(loadingEntry(linkedQuarantineID));
    setDetailTab("summary");
    setBlockSenderResult(null);
  }, [linkedQuarantineID, detailPreview?.id]);

  function closeDetail() {
    setDetailPreview(null);
    setBlockSenderResult(null);
    setBlockDialog(null);
    if (!linkedQuarantineID) return;
    const next = new URLSearchParams(urlParams);
    next.delete("id");
    setUrlParams(next, { replace: true });
  }

  function openBlockDomainDialog(entry: QuarantineEntry, match: Extract<BlockMatch, "domain" | "root_domain">) {
    const sender = entry.from_addr ?? "";
    const domain = senderDomain(sender);
    const target = match === "root_domain" ? rootDomainCandidate(domain) : domain;
    setBlockSenderResult(null);
    blockSender.reset();
    setBlockDialog({
      id: entry.id,
      match,
      sender,
      pattern: target ? `*@${target}` : "",
      verdict: currentThreatVerdict(entry),
    });
  }

  function submitBlockDialog(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!blockDialog) return;
    const pattern = normalizeDomainPattern(blockDialog.pattern);
    if (!pattern) return;
    blockSender.mutate({ id: blockDialog.id, match: "domain", verdict: blockDialog.verdict, pattern });
  }

  function toggleOne(id: string, checked: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  }

  function toggleVisible(checked: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      for (const id of visibleIDs) {
        if (checked) next.add(id); else next.delete(id);
      }
      return next;
    });
  }

  const columns: ColumnDef<QuarantineEntry>[] = [
    {
      key: "select",
      header: <span className="sr-only">Select</span>,
      label: "Select",
      width: 4,
      sortable: false,
      className: "w-[3rem] whitespace-nowrap",
      render: (entry) => (
        <input
          type="checkbox"
          aria-label={`Select ${entry.subject || entry.from_addr || "quarantined message"}`}
          checked={selected.has(entry.id)}
          onChange={(event) => toggleOne(entry.id, event.target.checked)}
        />
      ),
    },
    {
      key: "received",
      header: "Received",
      width: 17,
      className: "w-[11rem] whitespace-nowrap",
      sortValue: (entry) => entry.received_at,
      render: (entry) => <span title={new Date(entry.received_at).toLocaleString()}>{formatDate(entry.received_at)}</span>,
    },
    {
      key: "from",
      header: "From",
      width: 32,
      className: "max-w-[16rem] whitespace-nowrap",
      sortValue: (entry) => entry.from_addr ?? "",
      render: (entry) => <span className="block truncate" title={entry.from_addr}>{entry.from_addr ?? "—"}</span>,
    },
    {
      key: "subject",
      header: "Subject",
      width: 39,
      className: "max-w-[28rem] whitespace-nowrap",
      sortValue: (entry) => entry.subject ?? "",
      render: (entry) => <span className="block truncate" title={entry.subject}>{entry.subject ?? "—"}</span>,
    },
    {
      key: "score",
      header: "Score",
      width: 6,
      className: "w-[5rem] text-right tabular-nums whitespace-nowrap",
      sortValue: (entry) => entry.rspamd_score,
      render: (entry) => entry.rspamd_score?.toFixed(1) ?? "—",
    },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">Quarantine</h1>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="grid gap-3 grid-cols-1 md:grid-cols-3">
            <label className="text-sm">
              <span className="block mb-1">State</span>
              <select
                value={state}
                onChange={(e) => {
                  setOffset(0);
                  setState(e.target.value);
                }}
                className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              >
                <option value="">all</option>
                <option value="held">held</option>
                <option value="released">released</option>
                <option value="deleted">deleted</option>
                <option value="expired">expired</option>
              </select>
            </label>
            <label className="text-sm md:col-span-2">
              <span className="block mb-1">Search</span>
              <Input
                value={search}
                onChange={(e) => {
                  setOffset(0);
                  setSearch(e.target.value);
                }}
                placeholder="subject, sender, recipient, or message content"
              />
            </label>
          </div>
        </CardBody>
      </Card>

      {error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Failed to load: {error instanceof Error ? error.message : "unknown"}
        </div>
      )}
      {release.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Release failed: {release.error instanceof Error ? release.error.message : "unknown"}
        </div>
      )}
      {del.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Delete failed: {del.error instanceof Error ? del.error.message : "unknown"}
        </div>
      )}
      {bulk.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Bulk action failed: {bulk.error instanceof Error ? bulk.error.message : "unknown"}
        </div>
      )}
      {bulkResult && (
        <div role="status" className="mb-4 rounded border border-border bg-muted px-3 py-2 text-sm">
          <div>{bulkResult.message}</div>
          {bulkResult.queued && bulkResult.notify_to && (
            <div>Completion email will be sent to <span className="font-mono">{bulkResult.notify_to}</span>.</div>
          )}
          {!bulkResult.queued && bulkResult.email_sent_to && bulkResult.email_sent_to.length > 0 && (
            <div>Email sent to <span className="font-mono break-all">{bulkResult.email_sent_to.join(", ")}</span>.</div>
          )}
        </div>
      )}
      {prepareSourceIPReport.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Source IP report failed: {prepareSourceIPReport.error instanceof Error ? prepareSourceIPReport.error.message : "unknown"}
        </div>
      )}
      {blockSender.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Block sender failed: {blockSender.error instanceof Error ? blockSender.error.message : "unknown"}
        </div>
      )}
      {allowSender.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Whitelist failed: {allowSender.error instanceof Error ? allowSender.error.message : "unknown"}
        </div>
      )}
      {purgeExpired.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          Purge failed: {purgeExpired.error instanceof Error ? purgeExpired.error.message : "unknown"}
        </div>
      )}
      {purgeResult && (
        <div role="status" className="mb-4 rounded border border-border bg-muted px-3 py-2 text-sm">
          Purged {purgeResult.purged_entries.toLocaleString()} expired quarantine entries and {purgeResult.purged_blobs.toLocaleString()} stored messages.
        </div>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-3 rounded border border-border bg-surface px-3 py-2 text-sm shadow-sm">
        <label className="inline-flex items-center gap-2">
          <input
            type="checkbox"
            aria-label="Select all visible quarantine messages"
            checked={allVisibleSelected}
            disabled={visibleIDs.length === 0}
            onChange={(event) => toggleVisible(event.target.checked)}
          />
          <span>{selectedCount} selected</span>
        </label>
        {selectedCount > 0 ? (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "release" })}>
              Release selected
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_sender" })}>
              Block senders
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_domain" })}>
              Block sender domains
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_root_domain" })}>
              Block root domains
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "report_source_ip" })}>
              Report source IPs
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "mark_spam" })}>
              Mark spam
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "mark_phishing" })}>
              Mark phishing
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "mark_malware" })}>
              Mark malware
            </Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "mark_other" })}>
              Mark other
            </Button>
            <Button size="sm" variant="danger" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "delete" })}>
              Delete selected
            </Button>
          </div>
        ) : (
          <span className="text-subtle">Select messages to release or delete more than one quarantined item at a time.</span>
        )}
        {canPurgeExpired && (
          <Button size="sm" variant="secondary" disabled={purgeExpired.isPending} onClick={() => purgeExpired.mutate()}>
            {purgeExpired.isPending ? "Purging…" : "Purge expired"}
          </Button>
        )}
      </div>

      <DataTable
        columns={columns}
        rows={data?.items}
        loading={isLoading}
        empty="No messages in quarantine."
        rowKey={(entry) => entry.id}
        initialSortDirection="desc"
        actionColumnWidth={26}
        manualPagination={{
          total: data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
        actions={(entry) => (
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                setDetailPreview(entry);
                setDetailTab("summary");
                setBlockSenderResult(null);
              }}
            >
              Details
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={currentQuarantineVerdict(entry) === "not_spam" || !entry.from_addr || notSpam.isPending}
              onClick={() => notSpam.mutate(entry.id)}
            >
              Not spam
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!entry.from_addr || allowSender.isPending}
              onClick={() => allowSender.mutate({ id: entry.id, match: "domain" })}
            >
              Whitelist
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={!entry.can_release || release.isPending}
              onClick={() => release.mutate(entry.id)}
            >
              {isChallengeResponseEntry(entry) ? "Allow sender" : "Release"}
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={del.isPending}
              onClick={() => del.mutate(entry.id)}
            >
              Delete
            </Button>
          </div>
        )}
      />

      {detailItem && (
        <Modal open onClose={closeDetail} title={detailItem.subject || "(no subject)"} xl>
          <div className="grid gap-4">
            {detail.error && (
              <div role="alert" className="text-sm text-danger">
                Detail failed: {detail.error instanceof Error ? detail.error.message : "unknown"}
              </div>
            )}
            <div className="flex flex-wrap gap-2 border-b border-border">
              {(["summary", "analysis", "headers", "content"] as DetailTab[]).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setDetailTab(tab)}
                  className={`rounded-t px-3 py-2 text-sm font-medium capitalize focus:outline-none focus-visible:ring-2 focus-visible:ring-focus ${
                    detailTab === tab ? "bg-muted text-fg" : "text-subtle hover:text-fg"
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
            {detailTab === "summary" && (
              <div className="grid gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Message details</CardTitle>
                  </CardHeader>
                  <CardBody>
                    <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-[9rem_minmax(0,1fr)]">
                      <dt className="text-subtle">Received</dt>
                      <dd className="min-w-0">{new Date(detailItem.received_at).toLocaleString()}</dd>
                      <dt className="text-subtle">From</dt>
                      <dd className="min-w-0 break-all">{detailItem.from_addr ?? "—"}</dd>
                      <dt className="text-subtle">To</dt>
                      <dd className="min-w-0 break-all">{detailItem.to_addr}</dd>
                      <dt className="text-subtle">Subject</dt>
                      <dd className="min-w-0 break-words">{detailItem.subject ?? "—"}</dd>
                      <dt className="text-subtle">Source IP</dt>
                      <dd className="min-w-0 break-all">{detailItem.client_ip ?? "—"}</dd>
                      <dt className="text-subtle">Sender auth</dt>
                      <dd className="min-w-0">{detailItem.spoof_warning ? "Possible spoof" : "No spoof signal detected"}</dd>
                      <dt className="text-subtle">Size</dt>
                      <dd>{formatBytes(detailItem.size_bytes)}</dd>
                      <dt className="text-subtle">Storage</dt>
                      <dd>{detailItem.has_blob ? "Original message stored" : "No stored original message"}</dd>
                      <dt className="text-subtle">Classification</dt>
                      <dd>{displayQuarantineVerdict(detailItem)}</dd>
                      <dt className="text-subtle">Release status</dt>
                      <dd>{detailItem.can_release ? "Ready to release." : detailItem.has_blob ? "Message is not currently held." : "Original message was not stored."}</dd>
                      <dt className="text-subtle">Expires</dt>
                      <dd>{detailItem.expires_at ? new Date(detailItem.expires_at).toLocaleString() : "—"}</dd>
                      <dt className="text-subtle">Released</dt>
                      <dd>{detailItem.released_at ? new Date(detailItem.released_at).toLocaleString() : "—"}</dd>
                    </dl>
                  </CardBody>
                </Card>
              </div>
            )}
            {detailTab === "analysis" && (
              <div className="grid gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Analysis</CardTitle>
                  </CardHeader>
                  <CardBody>
                    <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-[9rem_minmax(0,1fr)]">
                      <dt className="text-subtle">Type</dt>
                      <dd>{detailItem.email_type}</dd>
                      <dt className="text-subtle">Threat class</dt>
                      <dd>{detailItem.threat_class ?? "—"}</dd>
                      <dt className="text-subtle">Source IP</dt>
                      <dd className="break-all">{detailItem.client_ip ?? "—"}</dd>
                      <dt className="text-subtle">Rspamd score</dt>
                      <dd className="tabular-nums">{detailItem.rspamd_score?.toFixed(1) ?? "—"}</dd>
                      <dt className="text-subtle">State</dt>
                      <dd>{detailItem.state}</dd>
                      <dt className="text-subtle">Warning</dt>
                      <dd>{detailItem.scam_warning || "—"}</dd>
                      <dt className="text-subtle">Spoofing</dt>
                      <dd>{detailItem.spoof_warning || "—"}</dd>
                      <dt className="text-subtle">Signals</dt>
                      <dd>
                        {[...(detailItem.spoof_signals ?? []), ...(detailItem.scam_signals ?? [])].length > 0 ? (
                          <ul className="list-disc pl-4">
                            {[...(detailItem.spoof_signals ?? []), ...(detailItem.scam_signals ?? [])].map((signal) => <li key={signal}>{signal}</li>)}
                          </ul>
                        ) : "—"}
                      </dd>
                    </dl>
                  </CardBody>
                </Card>
                <SpoofWarning item={detailItem} />
                <ScamGuidance item={detailItem} />
              </div>
            )}
            {detailTab === "headers" && (
              <div className="grid gap-2">
                {(detailItem.headers ?? []).length === 0 && (
                  <div className="text-sm text-subtle">No stored headers are available for this quarantine entry.</div>
                )}
                {(detailItem.headers ?? []).map((header, index) => (
                  <div key={`${header.name}-${index}`} className="grid gap-1 rounded border border-border bg-muted/40 p-2 text-sm md:grid-cols-[12rem_minmax(0,1fr)]">
                    <div className="font-mono text-xs font-semibold text-subtle">{header.name}</div>
                    <div className="min-w-0 whitespace-pre-wrap break-words font-mono text-xs">{header.value}</div>
                  </div>
                ))}
              </div>
            )}
            {detailTab === "content" && (
              <div className="grid gap-4">
                <section aria-label="Message content">
                  <h3 className="mb-2 text-sm font-semibold">Content</h3>
                  <PreBlock value={detailItem.content_text || "No stored message content is available for this quarantine entry."} />
                </section>
                <section aria-label="Raw message excerpt">
                  <h3 className="mb-2 text-sm font-semibold">Raw excerpt</h3>
                  <PreBlock value={detailItem.raw_excerpt || "No stored raw message is available for this quarantine entry."} />
                </section>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.client_ip || prepareSourceIPReport.isPending}
                onClick={() => {
                  prepareSourceIPReport.reset();
                  sendSourceIPReport.reset();
                  setSourceIPReportEntry(detailItem);
                  setSourceIPReport(null);
                  prepareSourceIPReport.mutate(detailItem.id);
                }}
              >
                {prepareSourceIPReport.isPending ? "Looking up…" : "Report source IP"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.from_addr || allowSender.isPending}
                onClick={() => allowSender.mutate({ id: detailItem.id, match: "domain" })}
              >
                {allowSender.isPending ? "Whitelisting…" : "Whitelist domain"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.from_addr || allowSender.isPending}
                onClick={() => allowSender.mutate({ id: detailItem.id, match: "root_domain" })}
              >
                Whitelist root domain
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.from_addr || blockSender.isPending}
                onClick={() => blockSender.mutate({ id: detailItem.id, match: "sender", verdict: currentThreatVerdict(detailItem) })}
              >
                {blockSender.isPending ? "Blocking…" : detailIsChallenge ? "Deny sender" : "Block sender"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.from_addr || blockSender.isPending}
                onClick={() => openBlockDomainDialog(detailItem, "domain")}
              >
                Block sender domain
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.from_addr || blockSender.isPending}
                onClick={() => openBlockDomainDialog(detailItem, "root_domain")}
              >
                Block root domain
              </Button>
              {QUARANTINE_VERDICTS.map((v) => {
                const active = currentQuarantineVerdict(detailItem) === v.value;
                return (
                  <Button
                    key={v.value}
                    size="sm"
                    variant={active ? "primary" : "secondary"}
                    disabled={active || setQuarantineVerdict.isPending}
                    onClick={() => setQuarantineVerdict.mutate({ id: detailItem.id, verdict: v.value })}
                  >
                    {active ? `${v.label} marked` : `Mark ${v.label.toLowerCase()}`}
                  </Button>
                );
              })}
              <Button
                size="sm"
                variant="secondary"
                disabled={currentQuarantineVerdict(detailItem) === "not_spam" || !detailItem.from_addr || notSpam.isPending}
                onClick={() => notSpam.mutate(detailItem.id)}
              >
                Mark not spam
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detailItem.can_release || release.isPending}
                onClick={() => release.mutate(detailItem.id)}
              >
                {detailIsChallenge ? "Allow sender and release" : "Release"}
              </Button>
              <Button
                size="sm"
                variant="danger"
                disabled={del.isPending}
                onClick={() => del.mutate(detailItem.id)}
              >
                Delete
              </Button>
            </div>
            {blockSenderResult && (
              <div role="status" className="rounded border border-border bg-muted px-3 py-2 text-sm">
                {blockSenderResult.message} Pattern: <span className="font-mono">{blockSenderResult.pattern}</span> ({blockSenderResult.scope}
                {blockSenderResult.existing ? ", already existed" : ""}).
              </div>
            )}
          </div>
        </Modal>
      )}
      {blockDialog && (
        <Modal
          open
          onClose={() => setBlockDialog(null)}
          title={blockDialog.match === "root_domain" ? "Block root domain" : "Block sender domain"}
          footer={
            <>
              <Button type="button" variant="secondary" onClick={() => setBlockDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" form="quarantine-block-domain-form" disabled={blockSender.isPending || !normalizeDomainPattern(blockDialog.pattern)}>
                {blockSender.isPending ? "Blocking…" : "Block domain"}
              </Button>
            </>
          }
        >
          <form id="quarantine-block-domain-form" onSubmit={submitBlockDialog} className="grid gap-3">
            <div className="text-sm">
              <div className="text-subtle">Sender</div>
              <div className="break-all font-mono">{blockDialog.sender}</div>
            </div>
            <label className="text-sm">
              <span className="mb-1 block text-subtle">Pattern to block</span>
              <input
                autoFocus
                value={blockDialog.pattern}
                onChange={(event) => setBlockDialog((current) => current ? { ...current, pattern: event.target.value } : current)}
                placeholder="*@example.com"
                className="block w-full rounded border border-border bg-surface px-3 py-2 font-mono text-fg placeholder:text-subtle"
              />
            </label>
            <p className="text-sm text-subtle">
              Use <span className="font-mono">*@domain.com</span> to block all mail from that domain and its subdomains.
            </p>
          </form>
        </Modal>
      )}
      {sourceIPReportEntry && (
        <Modal open onClose={() => {
          prepareSourceIPReport.reset();
          sendSourceIPReport.reset();
          setSourceIPReportEntry(null);
          setSourceIPReport(null);
        }} title="Report source IP" xl>
          <div className="grid gap-4">
            {prepareSourceIPReport.isPending && <div className="text-sm text-subtle">Looking up abuse contact…</div>}
            {prepareSourceIPReport.error && (
              <div role="alert" className="text-sm text-danger">
                Lookup failed: {prepareSourceIPReport.error instanceof Error ? prepareSourceIPReport.error.message : "unknown"}
              </div>
            )}
            {sendSourceIPReport.error && (
              <div role="alert" className="text-sm text-danger">
                Send failed: {sendSourceIPReport.error instanceof Error ? sendSourceIPReport.error.message : "unknown"}
              </div>
            )}
            {sourceIPReport && (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>Abuse report</CardTitle>
                  </CardHeader>
                  <CardBody>
                    <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-[10rem_minmax(0,1fr)]">
                      <dt className="text-subtle">Source IP</dt>
                      <dd className="break-all">{sourceIPReport.ip}</dd>
                      <dt className="text-subtle">Network</dt>
                      <dd>{sourceIPReport.network_name || "—"}</dd>
                      <dt className="text-subtle">Abuse contact</dt>
                      <dd className="break-all">{sourceIPReport.abuse_contacts.length ? sourceIPReport.abuse_contacts.join(", ") : "—"}</dd>
                      <dt className="text-subtle">Outbound relay</dt>
                      <dd>{sourceIPReport.outbound_server || "—"}</dd>
                      <dt className="text-subtle">Status</dt>
                      <dd>
                        {sourceIPReport.sent
                          ? `Email sent to ${(sourceIPReport.sent_to?.length ? sourceIPReport.sent_to : sourceIPReport.abuse_contacts).join(", ")}.`
                          : sourceIPReport.submission_mode === "webform"
                            ? "Webform submission required."
                          : sourceIPReport.warning || "Ready to send."}
                      </dd>
                    </dl>
                  </CardBody>
                </Card>
                {sourceIPReport.webform && (
                  <Card>
                    <CardHeader>
                      <CardTitle>{sourceIPReport.webform.provider} webform fields</CardTitle>
                    </CardHeader>
                    <CardBody>
                      <div className="grid gap-3 text-sm">
                        <CopyField label="Type of abuse" value={sourceIPReport.webform.abuse_type} />
                        {sourceIPReport.webform.abuse_subtype && <CopyField label="Subtype" value={sourceIPReport.webform.abuse_subtype} />}
                        <CopyField label="IP address of the reported content" value={sourceIPReport.webform.reported_ip} />
                        <CopyField label="Date of incident" value={sourceIPReport.webform.date_of_incident} />
                        {sourceIPReport.webform.contact_name && <CopyField label="Name" value={sourceIPReport.webform.contact_name} />}
                        {sourceIPReport.webform.contact_email && <CopyField label="Email" value={sourceIPReport.webform.contact_email} />}
                        {sourceIPReport.webform.company_name && <CopyField label="Company name" value={sourceIPReport.webform.company_name} />}
                        {sourceIPReport.webform.phone_number && <CopyField label="Phone number" value={sourceIPReport.webform.phone_number} />}
                        {sourceIPReport.webform.attachment_note && <CopyField label="Attachment" value={sourceIPReport.webform.attachment_note} />}
                        {sourceIPReport.webform.privacy_confirmation && <CopyField label="Privacy confirmation" value={sourceIPReport.webform.privacy_confirmation} />}
                        {sourceIPReport.webform.accuracy_confirmation && <CopyField label="Accuracy confirmation" value={sourceIPReport.webform.accuracy_confirmation} />}
                        <section aria-label="Worldstream additional information">
                          <div className="mb-2 flex items-center justify-between gap-2">
                            <h3 className="text-sm font-semibold">Additional information</h3>
                            <Button size="sm" variant="secondary" onClick={() => writeClipboard(sourceIPReport.webform!.additional_information)}>
                              Copy
                            </Button>
                          </div>
                          <PreBlock value={sourceIPReport.webform.additional_information} />
                        </section>
                      </div>
                    </CardBody>
                  </Card>
                )}
                <section aria-label="Prepared abuse report">
                  <h3 className="mb-2 text-sm font-semibold">Prepared report</h3>
                  <PreBlock value={sourceIPReport.report_body} />
                </section>
                <div className="flex flex-wrap gap-2">
                  {sourceIPReport.webform ? (
                    <>
                      <Button
                        size="sm"
                        onClick={() => window.open(safeWorldstreamURL(sourceIPReport.webform!.url), "_blank", "noopener,noreferrer")}
                      >
                        Open webform
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => writeClipboard(formatWebformFields(sourceIPReport.webform!))}
                      >
                        Copy form fields
                      </Button>
                    </>
                  ) : (
                    <Button
                      size="sm"
                      disabled={!sourceIPReport.can_send || sendSourceIPReport.isPending || sourceIPReport.sent}
                      onClick={() => sendSourceIPReport.mutate(sourceIPReportEntry.id)}
                    >
                      {sendSourceIPReport.isPending ? "Sending…" : sourceIPReport.sent ? "Sent" : "Send report"}
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => writeClipboard(sourceIPReport.report_body)}
                  >
                    Copy report
                  </Button>
                </div>
              </>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}

function loadingEntry(id: string): QuarantineEntry {
  return {
    id,
    organization_id: "",
    to_addr: "",
    state: "loading",
    has_blob: false,
    can_release: false,
    email_type: "Loading",
    received_at: new Date().toISOString(),
  };
}

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 rounded border border-border bg-surface p-3 md:grid-cols-[12rem_minmax(0,1fr)_auto] md:items-center">
      <div className="text-subtle">{label}</div>
      <div className="break-words font-mono text-xs">{value || "—"}</div>
      <Button size="sm" variant="secondary" onClick={() => writeClipboard(value)} disabled={!value}>
        Copy
      </Button>
    </div>
  );
}

function writeClipboard(value: string) {
  void navigator.clipboard?.writeText(value);
}

function safeWorldstreamURL(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "https:" && parsed.hostname === "www.worldstream.com" && parsed.pathname.startsWith("/en/abuse/")) {
      return parsed.toString();
    }
  } catch {
    // Fall through to the known-good form URL.
  }
  return "https://www.worldstream.com/en/abuse/abuse-form/";
}

function formatWebformFields(form: SourceIPWebform): string {
  const lines = [
    `Type of abuse: ${form.abuse_type}`,
    form.abuse_subtype ? `Subtype: ${form.abuse_subtype}` : "",
    `IP address of the reported content: ${form.reported_ip}`,
    `Date of incident: ${form.date_of_incident}`,
    form.contact_name ? `Name: ${form.contact_name}` : "",
    form.contact_email ? `Email: ${form.contact_email}` : "",
    form.company_name ? `Company name: ${form.company_name}` : "",
    form.phone_number ? `Phone number: ${form.phone_number}` : "",
    form.attachment_note ? `Attachment: ${form.attachment_note}` : "",
    "",
    "Additional information:",
    form.additional_information,
  ];
  return lines.filter((line) => line !== "").join("\n");
}

function senderDomain(sender: string): string {
  const trimmed = sender.trim().toLowerCase();
  const address = trimmed.includes("<") && trimmed.includes(">")
    ? trimmed.replace(/^.*<([^>]+)>.*$/, "$1")
    : trimmed;
  const at = address.lastIndexOf("@");
  if (at < 0) return "";
  return address.slice(at + 1).replace(/[>\s]+$/g, "").replace(/\.$/, "");
}

function rootDomainCandidate(domain: string): string {
  const labels = domain.split(".").filter(Boolean);
  if (labels.length <= 2) return domain;
  return labels.slice(-2).join(".");
}

function normalizeDomainPattern(value: string): string {
  const raw = value.trim().toLowerCase();
  const domain = raw.replace(/^\*@/, "").replace(/^@/, "").replace(/\.$/, "");
  if (!domain || domain.includes("@") || domain.includes("/") || domain.includes(":") || !domain.includes(".")) return "";
  return `*@${domain}`;
}

function isChallengeResponseEntry(entry: QuarantineEntry): boolean {
  return entry.threat_class === "CHALLENGE_RESPONSE" || entry.email_type === "CHALLENGE_RESPONSE";
}

function currentQuarantineVerdict(entry: QuarantineEntry): DisplayVerdict {
  const value = `${entry.threat_class ?? ""} ${entry.email_type ?? ""}`.toLowerCase();
  if (value.includes("not_spam") || value.includes("not spam")) return "not_spam";
  if (value.includes("malware") || value.includes("virus")) return "malware";
  if (value.includes("phishing")) return "phishing";
  if (value.includes("spam")) return "spam";
  return "other";
}

function currentThreatVerdict(entry: QuarantineEntry): QuarantineVerdict {
  const verdict = currentQuarantineVerdict(entry);
  return verdict === "not_spam" ? "other" : verdict;
}

function displayQuarantineVerdict(entry: QuarantineEntry): string {
  const verdict = currentQuarantineVerdict(entry);
  return verdict === "not_spam" ? "not spam" : verdict;
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString([], {
    month: "numeric",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function PreBlock({ value }: { value: string }) {
  return (
    <pre className="max-h-[34rem] overflow-auto rounded border border-border bg-muted p-3 whitespace-pre-wrap break-words font-mono text-xs leading-relaxed">
      {value}
    </pre>
  );
}

function formatBytes(value?: number): string {
  if (value == null || !Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}
