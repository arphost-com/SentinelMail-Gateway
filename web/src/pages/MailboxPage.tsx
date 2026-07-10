import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { HelpTooltip } from "../components/ui/HelpTooltip";
import { Modal } from "../components/ui/Modal";
import { ScamGuidance } from "../components/ui/ScamGuidance";
import { SpoofWarning } from "../components/ui/SpoofWarning";
import { confirmDanger } from "../components/ui/confirm";

interface MailboxMessage {
  id: string;
  mail_log_id: string;
  from_addr?: string;
  to_addr: string;
  subject?: string;
  body_text: string;
  verdict: string;
  email_type: string;
  scam_warning?: string;
  scam_signals?: string[];
  scam_links?: Array<{ label: string; url: string }>;
  auth_status?: string;
  spoof_warning?: string;
  spoof_signals?: string[];
  unsubscribe?: UnsubscribeInfo;
  verdict_at?: string;
  received_at: string;
}

interface UnsubscribeInfo {
  available: boolean;
  one_click?: boolean;
  options?: UnsubscribeOption[];
}

interface UnsubscribeOption {
  type: "url" | "mailto";
  label: string;
  url: string;
}

interface BlockSenderResponse {
  pattern: string;
  scope: string;
  match: string;
  message: string;
}

interface MailLogActionResponse {
  message: string;
  pattern?: string;
  scope?: string;
  released?: number;
  deleted?: number;
  failed?: number;
  sent_to?: string[];
  warning?: string;
  report_body?: string;
}

interface UnsubscribeResponse {
  message: string;
  type: "url" | "mailto";
  sent?: boolean;
  sent_to?: string[];
  status?: number;
  url?: string;
}

type BlockMatch = "sender" | "domain" | "root_domain";
type BulkAction = "delete" | "verdict" | "block_sender" | "block_domain" | "block_root_domain" | "allow_domain" | "allow_root_domain";

interface BlockDialogState {
  id: string;
  match: Extract<BlockMatch, "domain" | "root_domain">;
  sender: string;
  pattern: string;
}

const VERDICTS = [
  { value: "not_spam", label: "Not spam" },
  { value: "spam", label: "Spam" },
  { value: "phishing", label: "Phishing" },
  { value: "malware", label: "Malware" },
  { value: "other", label: "Other" },
];

export function MailboxPage() {
  const qc = useQueryClient();
  const [verdict, setVerdict] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [detail, setDetail] = useState<MailboxMessage | null>(null);
  const [limit, setLimit] = useState(10);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [bulkResult, setBulkResult] = useState<{ action: BulkAction; updated: number; deleted: number; failed?: number } | null>(null);
  const [blockResult, setBlockResult] = useState<BlockSenderResponse | null>(null);
  const [mailLogActionResult, setMailLogActionResult] = useState<MailLogActionResponse | null>(null);
  const [unsubscribeResult, setUnsubscribeResult] = useState<UnsubscribeResponse | null>(null);
  const [blockDialog, setBlockDialog] = useState<BlockDialogState | null>(null);

  const params = new URLSearchParams();
  if (verdict) params.set("verdict", verdict);
  if (search.trim()) params.set("q", search.trim());
  params.set("limit", String(limit));
  params.set("offset", String(offset));

  const list = useQuery({
    queryKey: ["mailbox", verdict, search, offset, limit],
    queryFn: () => api.get<ListResponse<MailboxMessage>>(`/mailbox?${params.toString()}`),
    refetchInterval: 30_000,
  });

  const setMessageVerdict = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      api.post<MailboxMessage>(`/mailbox/${id}/verdict`, { verdict: value }),
    onSuccess: (msg) => {
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      setDetail((current) => current && current.id === msg.id ? msg : current);
    },
  });

  const bulk = useMutation({
    mutationFn: ({ action, value }: { action: BulkAction; value?: string }) =>
      api.post<{ updated: number; deleted: number; failed?: number }>("/mailbox/bulk", {
        ids: Array.from(selected),
        action,
        verdict: value,
      }),
    onSuccess: (result, variables) => {
      setBulkResult({ action: variables.action, ...result });
      setSelected(new Set());
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      setDetail(null);
    },
  });

  const blockSender = useMutation({
    mutationFn: ({ id, match, pattern }: { id: string; match: BlockMatch; pattern?: string }) =>
      api.post<BlockSenderResponse>(`/mailbox/${id}/block-sender`, pattern ? { match, pattern } : { match }),
    onSuccess: (result) => {
      setBlockResult(result);
      setBlockDialog(null);
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
      setDetail((current) => current ? { ...current, verdict: "spam", email_type: "User reported spam" } : current);
    },
  });

  const allowSender = useMutation({
    mutationFn: ({ id, match }: { id: string; match: "domain" | "root_domain" }) =>
      api.post<BlockSenderResponse>(`/mailbox/${id}/allow-sender`, { match }),
    onSuccess: (result) => {
      setBlockResult(result);
      setBlockDialog(null);
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
      setDetail((current) => current ? { ...current, verdict: "not_spam", email_type: "User confirmed clean" } : current);
    },
  });

  const mailLogAction = useMutation({
    mutationFn: ({ mailLogID, action }: { mailLogID: string; action: string }) =>
      api.post<MailLogActionResponse>(`/mail-logs/${mailLogID}/${action}`, {}),
    onSuccess: (result) => {
      setMailLogActionResult(result);
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      qc.invalidateQueries({ queryKey: ["quarantine"] });
      qc.invalidateQueries({ queryKey: ["sender-lists"] });
    },
  });

  const deleteMessage = useMutation({
    mutationFn: (id: string) => api.del(`/mailbox/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mailbox"] });
      setDetail(null);
    },
  });

  const unsubscribe = useMutation({
    mutationFn: ({ id, option }: { id: string; option: UnsubscribeOption }) =>
      api.post<UnsubscribeResponse>(`/mailbox/${id}/unsubscribe`, { type: option.type, url: option.url }),
    onSuccess: (result) => {
      setUnsubscribeResult(result);
      qc.invalidateQueries({ queryKey: ["sent-emails"] });
    },
  });

  const visibleIDs = useMemo(() => list.data?.items.map((m) => m.id) ?? [], [list.data?.items]);
  const selectedCount = selected.size;
  const allVisibleSelected = visibleIDs.length > 0 && visibleIDs.every((id) => selected.has(id));

  useEffect(() => {
    setSelected((current) => {
      const visible = new Set(visibleIDs);
      const next = new Set(Array.from(current).filter((id) => visible.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [visibleIDs]);

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

  function openDetail(message: MailboxMessage) {
    setDetail(message);
    setBlockResult(null);
    setMailLogActionResult(null);
    setUnsubscribeResult(null);
    setBlockDialog(null);
    mailLogAction.reset();
    unsubscribe.reset();
    allowSender.reset();
  }

  function openBlockDomainDialog(message: MailboxMessage, match: Extract<BlockMatch, "domain" | "root_domain">) {
    const sender = message.from_addr ?? "";
    const domain = senderDomain(sender);
    const target = match === "root_domain" ? rootDomainCandidate(domain) : domain;
    setBlockResult(null);
    blockSender.reset();
    setBlockDialog({
      id: message.id,
      match,
      sender,
      pattern: target ? `*@${target}` : "",
    });
  }

  function submitBlockDialog(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!blockDialog) return;
    const pattern = normalizeDomainPattern(blockDialog.pattern);
    if (!pattern) return;
    blockSender.mutate({ id: blockDialog.id, match: "domain", pattern });
  }

  const columns: ColumnDef<MailboxMessage>[] = [
    {
      key: "select",
      header: <span className="sr-only">Select</span>,
      label: "Select",
      width: 5,
      sortable: false,
      className: "whitespace-nowrap",
      render: (m) => (
        <input
          type="checkbox"
          aria-label={`Select ${m.subject || m.from_addr || "message"}`}
          checked={selected.has(m.id)}
          onChange={(event) => toggleOne(m.id, event.target.checked)}
        />
      ),
    },
    {
      key: "received",
      header: "Received",
      width: 20,
      className: "whitespace-nowrap",
      sortValue: (m) => m.received_at,
      render: (m) => new Date(m.received_at).toLocaleString(),
    },
    {
      key: "from",
      header: "From",
      width: 36,
      className: "whitespace-nowrap",
      sortValue: (m) => m.from_addr ?? "",
      render: (m) => <span className="block truncate" title={m.from_addr ?? "Unknown sender"}>{m.from_addr ?? "—"}</span>,
    },
    {
      key: "subject",
      header: "Subject",
      width: 39,
      className: "whitespace-nowrap",
      sortValue: (m) => m.subject ?? "",
      render: (m) => <span className="block truncate" title={m.subject || "(none)"}>{m.subject ?? <span className="text-subtle">(none)</span>}</span>,
    },
  ];

  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold mb-1">Mailbox</h1>
          <p className="text-sm text-subtle">Messages addressed to your signed-in email address.</p>
        </div>
        <div className="grid gap-2 sm:grid-cols-[minmax(14rem,22rem)_auto]">
          <label className="text-sm">
            <span className="block text-subtle mb-1">Search inbox</span>
            <input
              value={search}
              onChange={(e) => {
                setOffset(0);
                setSearch(e.target.value);
              }}
              placeholder="sender, subject, body"
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg placeholder:text-subtle"
            />
          </label>
          <label className="text-sm">
            <span className="mb-1 inline-flex items-center gap-2 text-subtle">
              <span>Verdict</span>
              <HelpTooltip text="Filter by your review decision. Marking a held message as Not spam can release it to your mailbox if the original message is stored." />
            </span>
            <select
              value={verdict}
              onChange={(e) => {
                setOffset(0);
                setVerdict(e.target.value);
              }}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">all</option>
              <option value="unreviewed">unreviewed</option>
              {VERDICTS.map((v) => <option key={v.value} value={v.value}>{v.label}</option>)}
            </select>
          </label>
        </div>
      </div>

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {list.error instanceof Error ? list.error.message : "Failed to load mailbox"}
        </div>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-3 rounded border border-border bg-surface px-3 py-2 text-sm shadow-sm">
        <label className="inline-flex items-center gap-2">
          <input
            type="checkbox"
            aria-label="Select all visible inbox messages"
            checked={allVisibleSelected}
            disabled={visibleIDs.length === 0}
            onChange={(event) => toggleVisible(event.target.checked)}
          />
          <span>{selectedCount} selected</span>
        </label>
        {selectedCount > 0 ? (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "verdict", value: "not_spam" })}>Not spam</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "verdict", value: "spam" })}>Mark spam</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "verdict", value: "phishing" })}>Mark phishing</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "verdict", value: "malware" })}>Mark malware</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "verdict", value: "other" })}>Mark other</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_sender" })}>Block senders</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_domain" })}>Block domains</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "block_root_domain" })}>Block root domains</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "allow_domain" })}>Whitelist domains</Button>
            <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "allow_root_domain" })}>Whitelist root domains</Button>
            <Button size="sm" variant="danger" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "delete" })}>Delete</Button>
          </div>
        ) : (
          <span className="text-subtle">Select messages to mark, block senders or domains, or delete.</span>
        )}
      </div>

      {bulk.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          Bulk action failed: {bulk.error instanceof Error ? bulk.error.message : "unknown"}
        </div>
      )}
      {bulkResult && (
        <div role="status" className="mb-3 rounded border border-border bg-muted px-3 py-2 text-sm">
          {bulkResult.deleted > 0
            ? `${bulkResult.deleted} message${bulkResult.deleted === 1 ? "" : "s"} deleted.`
            : bulkResult.action === "block_sender" || bulkResult.action === "block_domain" || bulkResult.action === "block_root_domain"
              ? `${bulkResult.updated} sender block${bulkResult.updated === 1 ? "" : "s"} added.`
              : bulkResult.action === "allow_domain" || bulkResult.action === "allow_root_domain"
                ? `${bulkResult.updated} sender whitelist${bulkResult.updated === 1 ? "" : "s"} added.`
              : `${bulkResult.updated} message${bulkResult.updated === 1 ? "" : "s"} updated.`}
          {bulkResult.failed ? ` ${bulkResult.failed} failed.` : ""}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No messages for your email address yet."
        rowKey={(m) => m.id}
        initialSortDirection="desc"
        actionColumnWidth={8}
        manualPagination={{
          total: list.data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
        actions={(m) => <Button size="sm" variant="secondary" onClick={() => openDetail(m)}>Read</Button>}
      />

      {detail && (
        <Modal
          open
          onClose={() => {
            setDetail(null);
            setBlockResult(null);
            setMailLogActionResult(null);
            setUnsubscribeResult(null);
            mailLogAction.reset();
            unsubscribe.reset();
            allowSender.reset();
            deleteMessage.reset();
          }}
          title={detail.subject || "(no subject)"}
          wide
        >
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Message</CardTitle>
              </CardHeader>
              <CardBody>
                <dl className="grid grid-cols-3 gap-2 text-sm">
                  <dt className="text-subtle">Received</dt>
                  <dd className="col-span-2">{new Date(detail.received_at).toLocaleString()}</dd>
                  <dt className="text-subtle">From</dt>
                  <dd className="col-span-2 break-all">{detail.from_addr ?? "—"}</dd>
                  <dt className="text-subtle">To</dt>
                  <dd className="col-span-2 break-all">{detail.to_addr}</dd>
                  <dt className="text-subtle">Verdict</dt>
                  <dd className="col-span-2">{detail.verdict}</dd>
                  <dt className="text-subtle">Type</dt>
                  <dd className="col-span-2">{detail.email_type}</dd>
                  <dt className="text-subtle">Sender auth</dt>
                  <dd className="col-span-2">{detail.spoof_warning ? "Possible spoof" : "No spoof signal detected"}</dd>
                  <dt className="text-subtle">Mailing list</dt>
                  <dd className="col-span-2">
                    {detail.unsubscribe?.available ? (
                      <span>
                        Unsubscribe available{detail.unsubscribe.one_click ? " (one-click supported by sender)" : ""}
                      </span>
                    ) : (
                      <span className="text-subtle">No unsubscribe header captured</span>
                    )}
                  </dd>
                </dl>
              </CardBody>
            </Card>

            <SpoofWarning item={detail} />
            <ScamGuidance item={detail} />

            <div className="flex flex-wrap gap-2">
              {(detail.unsubscribe?.options ?? []).map((option) => (
                <span key={`${option.type}:${option.url}`} className="inline-flex items-center gap-1">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={unsubscribe.isPending}
                    onClick={() => handleUnsubscribe(detail.id, option, unsubscribe.mutate)}
                  >
                    {unsubscribeButtonLabel(option)}
                  </Button>
                  <HelpTooltip text={unsubscribeHelp(option)} />
                </span>
              ))}
              <Button
                size="sm"
                variant="secondary"
                disabled={mailLogAction.isPending}
                onClick={() => confirmDanger("Send a source IP abuse report for this inbox message?") && mailLogAction.mutate({ mailLogID: detail.mail_log_id, action: "source-ip-report" })}
              >
                Report source IP
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detail.from_addr || allowSender.isPending}
                onClick={() => allowSender.mutate({ id: detail.id, match: "domain" })}
              >
                {allowSender.isPending ? "Whitelisting..." : "Whitelist domain"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detail.from_addr || allowSender.isPending}
                onClick={() => allowSender.mutate({ id: detail.id, match: "root_domain" })}
              >
                Whitelist root domain
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detail.from_addr || blockSender.isPending}
                onClick={() => blockSender.mutate({ id: detail.id, match: "sender" })}
              >
                {blockSender.isPending ? "Blocking..." : "Block sender"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detail.from_addr || blockSender.isPending}
                onClick={() => openBlockDomainDialog(detail, "domain")}
              >
                Block domain
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!detail.from_addr || blockSender.isPending}
                onClick={() => openBlockDomainDialog(detail, "root_domain")}
              >
                Block root domain
              </Button>
              {VERDICTS.map((v) => (
                <span key={v.value} className="inline-flex items-center gap-1">
                  <Button
                    size="sm"
                    variant={detail.verdict === v.value ? "primary" : "secondary"}
                    disabled={setMessageVerdict.isPending}
                    onClick={() => setMessageVerdict.mutate({ id: detail.id, value: v.value })}
                  >
                    {v.label}
                  </Button>
                  <HelpTooltip text={verdictHelp(v.value)} />
                </span>
              ))}
              <Button
                size="sm"
                variant="secondary"
                disabled={mailLogAction.isPending}
                onClick={() => mailLogAction.mutate({ mailLogID: detail.mail_log_id, action: "release" })}
              >
                Release
              </Button>
              <Button
                size="sm"
                variant="danger"
                disabled={mailLogAction.isPending}
                onClick={() => confirmDanger("Delete held quarantine copies for this inbox message?") && mailLogAction.mutate({ mailLogID: detail.mail_log_id, action: "delete-held" })}
              >
                Delete held
              </Button>
              <Button
                size="sm"
                variant="danger"
                disabled={deleteMessage.isPending}
                onClick={() => confirmDanger("Delete this inbox copy?") && deleteMessage.mutate(detail.id)}
              >
                Delete from inbox
              </Button>
            </div>

            {blockSender.error && (
              <div role="alert" className="text-sm text-danger">
                Block failed: {blockSender.error instanceof Error ? blockSender.error.message : "unknown"}
              </div>
            )}
            {allowSender.error && (
              <div role="alert" className="text-sm text-danger">
                Whitelist failed: {allowSender.error instanceof Error ? allowSender.error.message : "unknown"}
              </div>
            )}
            {blockResult && (
              <div role="status" className="rounded border border-border bg-muted px-3 py-2 text-sm">
                {blockResult.message} Pattern: <span className="font-mono">{blockResult.pattern}</span> ({blockResult.scope}).
              </div>
            )}
            {mailLogAction.error && (
              <div role="alert" className="text-sm text-danger">
                Action failed: {mailLogAction.error instanceof Error ? mailLogAction.error.message : "unknown"}
              </div>
            )}
            {unsubscribe.error && (
              <div role="alert" className="text-sm text-danger">
                Unsubscribe failed: {unsubscribe.error instanceof Error ? unsubscribe.error.message : "unknown"}
              </div>
            )}
            {deleteMessage.error && (
              <div role="alert" className="text-sm text-danger">
                Delete failed: {deleteMessage.error instanceof Error ? deleteMessage.error.message : "unknown"}
              </div>
            )}
            {unsubscribeResult && (
              <div role="status" className="rounded border border-border bg-muted px-3 py-2 text-sm">
                <div>{unsubscribeResult.message}</div>
                {unsubscribeResult.sent_to && unsubscribeResult.sent_to.length > 0 && <div>Sent to: {unsubscribeResult.sent_to.join(", ")}</div>}
                {unsubscribeResult.status && <div>HTTP status: {unsubscribeResult.status}</div>}
              </div>
            )}
            {mailLogActionResult && (
              <div role="status" className="rounded border border-border bg-muted px-3 py-2 text-sm">
                <div>{mailLogActionResult.message}</div>
                {mailLogActionResult.pattern && <div>Pattern: <span className="font-mono">{mailLogActionResult.pattern}</span>{mailLogActionResult.scope ? ` (${mailLogActionResult.scope})` : ""}</div>}
                {(mailLogActionResult.released !== undefined || mailLogActionResult.deleted !== undefined || mailLogActionResult.failed !== undefined) && (
                  <div>
                    {mailLogActionResult.released !== undefined ? `Released: ${mailLogActionResult.released}. ` : ""}
                    {mailLogActionResult.deleted !== undefined ? `Deleted: ${mailLogActionResult.deleted}. ` : ""}
                    {mailLogActionResult.failed !== undefined ? `Failed: ${mailLogActionResult.failed}.` : ""}
                  </div>
                )}
                {mailLogActionResult.sent_to && mailLogActionResult.sent_to.length > 0 && <div>Sent to: {mailLogActionResult.sent_to.join(", ")}</div>}
                {mailLogActionResult.warning && <div className="text-warning">{mailLogActionResult.warning}</div>}
                {mailLogActionResult.report_body && <pre className="mt-2 max-h-48 overflow-auto rounded bg-surface p-2 text-xs whitespace-pre-wrap">{mailLogActionResult.report_body}</pre>}
              </div>
            )}

            <pre className="text-sm bg-muted p-4 rounded overflow-auto max-h-[28rem] whitespace-pre-wrap">
              {detail.body_text || "No message body text was captured for this message."}
            </pre>
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
              <Button type="submit" form="mailbox-block-domain-form" disabled={blockSender.isPending || !normalizeDomainPattern(blockDialog.pattern)}>
                {blockSender.isPending ? "Blocking..." : "Block domain"}
              </Button>
            </>
          }
        >
          <form id="mailbox-block-domain-form" onSubmit={submitBlockDialog} className="grid gap-3">
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
    </div>
  );
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

function handleUnsubscribe(
  messageID: string,
  option: UnsubscribeOption,
  submit: (payload: { id: string; option: UnsubscribeOption }) => void,
) {
  if (option.type === "url") {
    openUnsubscribeOption(option);
    return;
  }
  const prompt = option.type === "mailto"
    ? "Send an unsubscribe email for this mailing list?"
    : "Submit a one-click unsubscribe request for this mailing list?";
  if (confirmDanger(prompt)) {
    submit({ id: messageID, option });
  }
}

function openUnsubscribeOption(option: UnsubscribeOption) {
  const url = safeUnsubscribeURL(option);
  if (!url) return;
  if (option.type === "mailto") {
    window.location.assign(url);
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

function safeUnsubscribeURL(option: UnsubscribeOption) {
  if (option.type === "mailto") {
    return option.url.toLowerCase().startsWith("mailto:") && !hasControlChar(option.url) && !hasEncodedNewline(option.url) ? option.url : null;
  }
  try {
    const parsed = new URL(option.url);
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || !host.includes(".") || isLocalHost(host) || hasControlChar(option.url)) {
      return null;
    }
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function unsubscribeButtonLabel(option: UnsubscribeOption) {
  if (option.type === "mailto") return "Send unsubscribe email";
  return "Open unsubscribe page";
}

function unsubscribeHelp(option: UnsubscribeOption) {
  if (option.type === "mailto") {
    return "Sends an unsubscribe request through the configured outbound relay and records it in Sent Emails.";
  }
  return "Opens the validated HTTPS unsubscribe page from the message's List-Unsubscribe header in a new tab.";
}

function isLocalHost(host: string) {
  return host === "localhost" ||
    host.endsWith(".localhost") ||
    host.startsWith("127.") ||
    host === "[::1]" ||
    host === "::1" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);
}

function hasControlChar(value: string) {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function hasEncodedNewline(value: string) {
  return /%0a|%0d/i.test(value);
}

function verdictHelp(value: string) {
  switch (value) {
    case "not_spam":
      return "Marks this message as wanted mail and attempts to release a held quarantine copy for this recipient.";
    case "spam":
      return "Teaches SentinelMail that similar mail from this sender and subject pattern should be treated as spam for you.";
    case "phishing":
      return "Reports this as phishing, adds a phishing report, and teaches SentinelMail to warn on similar messages.";
    case "malware":
      return "Reports this as malware, adds a phishing or malware report, and teaches SentinelMail to warn on similar messages.";
    default:
      return "Stores your review decision for this message without treating it as a clean, spam, phishing, or malware example.";
  }
}
