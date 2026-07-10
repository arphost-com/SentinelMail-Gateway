import { DragEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ChartRow, HorizontalBars, StatTile } from "../components/ui/Charts";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Modal } from "../components/ui/Modal";

interface ScanJob {
  id: string;
  organization_id: string;
  mail_log_id?: string;
  kind: string;
  state: string;
  verdict?: string;
  error?: string;
  result?: Record<string, unknown> | null;
  payload?: Record<string, unknown> | null;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

const VERDICT_STYLE: Record<string, string> = {
  malicious: "border-danger/50 bg-danger/10 text-danger",
  suspicious: "border-warning/50 bg-warning/10 text-warning",
  clean: "border-success/50 bg-success/10 text-success",
};

const STATE_STYLE: Record<string, string> = {
  queued: "text-subtle",
  running: "text-warning",
  done: "text-fg",
  failed: "text-danger",
};

export function ThreatsPage() {
  const qc = useQueryClient();
  const [kind, setKind] = useState<string>("");
  const [state, setState] = useState<string>("");
  const [detail, setDetail] = useState<ScanJob | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitErr, setSubmitErr] = useState<string | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [showSubmit, setShowSubmit] = useState(false);

  const params = new URLSearchParams();
  if (kind) params.set("kind", kind);
  if (state) params.set("state", state);
  params.set("limit", "200");

  const list = useQuery({
    queryKey: ["scans", kind, state],
    queryFn: () => api.get<ListResponse<ScanJob>>(`/scan?${params.toString()}`),
    refetchInterval: 5000,
  });
  const visibleRows = list.data?.items ?? [];
  const stateRows = countRows(visibleRows, (job) => job.state);
  const verdictRows = countRows(visibleRows, (job) => job.verdict ?? "pending");
  const kindRows = countRows(visibleRows, (job) => job.kind);
  const visibleTotal = visibleRows.length;
  const inFlight = visibleRows.filter((job) => job.state === "queued" || job.state === "running").length;
  const completed = visibleRows.filter((job) => job.state === "done").length;
  const failed = visibleRows.filter((job) => job.state === "failed").length;

  const create = useMutation({
    mutationFn: (payload: { kind: string; payload: unknown }) => api.post<ScanJob>("/scan", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  const columns: ColumnDef<ScanJob>[] = [
    {
      key: "created",
      header: "Submitted",
      sortValue: (j) => j.created_at,
      render: (j) => new Date(j.created_at).toLocaleString(),
    },
    { key: "kind", header: "Kind", sortValue: (j) => j.kind, render: (j) => <code className="text-xs">{j.kind}</code> },
    {
      key: "state",
      header: "State",
      sortValue: (j) => j.state,
      render: (j) => <span className={STATE_STYLE[j.state] ?? ""}>{j.state}</span>,
    },
    {
      key: "verdict",
      header: "Verdict",
      sortValue: (j) => j.verdict ?? "",
      render: (j) =>
        j.verdict ? (
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${VERDICT_STYLE[j.verdict] ?? "border-border bg-muted"}`}>
            {j.verdict}
          </span>
        ) : (
          <span className="text-subtle">—</span>
        ),
    },
    {
      key: "summary",
      header: "Summary",
      sortValue: (j) => summarise(j),
      render: (j) => (
        <span className="text-xs text-subtle">
          {summarise(j)}
        </span>
      ),
    },
  ];

  async function submitImage() {
    if (!imageFile) return;
    setSubmitting(true);
    setSubmitErr(null);
    try {
      const b64 = await fileToBase64(imageFile);
      await create.mutateAsync({ kind: "qr", payload: { image_b64: b64 } });
      setImageFile(null);
      setShowSubmit(false);
    } catch (e) {
      setSubmitErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  }

  function selectImage(file: File | null) {
    setSubmitErr(null);
    if (!file) {
      setImageFile(null);
      return;
    }
    if (!file.type.startsWith("image/")) {
      setImageFile(null);
      setSubmitErr("Drop an image file: PNG, JPG, GIF, BMP, or WebP.");
      return;
    }
    setImageFile(file);
  }

  function handleImageDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    event.stopPropagation();
    selectImage(event.dataTransfer.files.item(0));
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold">Threat scans</h1>
          <p className="text-sm text-subtle">Background QR, browser sandbox, AI, and outbound-compromise scan jobs.</p>
        </div>
        <Button onClick={() => setShowSubmit(true)}>+ Scan QR image</Button>
      </div>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Kind">
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">all</option>
              <option value="qr">qr</option>
              <option value="sandbox">sandbox</option>
              <option value="ai">ai</option>
              <option value="outbound">outbound</option>
            </select>
          </Field>
          <Field label="State">
            <select
              value={state}
              onChange={(e) => setState(e.target.value)}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">all</option>
              <option value="queued">queued</option>
              <option value="running">running</option>
              <option value="done">done</option>
              <option value="failed">failed</option>
            </select>
          </Field>
        </CardBody>
      </Card>

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {list.error instanceof Error ? list.error.message : "Failed to load"}
        </div>
      )}

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-4 mb-4">
        <Metric label="Matching scans" value={list.data?.total} loading={list.isLoading} hint="current filters" />
        <Metric label="In flight" value={inFlight} loading={list.isLoading} total={visibleTotal} tone="warning" hint="visible queued or running" />
        <Metric label="Completed" value={completed} loading={list.isLoading} total={visibleTotal} tone="success" hint="visible done jobs" />
        <Metric label="Failed" value={failed} loading={list.isLoading} total={visibleTotal} tone="danger" hint="visible failed jobs" />
      </div>

      <div className="grid gap-4 grid-cols-1 xl:grid-cols-3 mb-4">
        <Card>
          <CardHeader>
            <CardTitle>Scan state</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={stateRows} empty="No scan state data for the current filters." label="Visible scan states" capitalize />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Verdicts</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={verdictRows} empty="No verdict data for the current filters." label="Visible scan verdicts" capitalize />
          </CardBody>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Scan types</CardTitle>
          </CardHeader>
          <CardBody>
            <HorizontalBars rows={kindRows} empty="No scan type data for the current filters." label="Visible scan types" monospace />
          </CardBody>
        </Card>
      </div>

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No scans yet. Use “Scan QR image” to test the pipeline."
        rowKey={(j) => j.id}
        initialSortDirection="desc"
        actions={(j) => (
          <Button size="sm" variant="secondary" onClick={() => setDetail(j)}>Details</Button>
        )}
      />

      {detail && (
        <Modal open onClose={() => setDetail(null)} title={`Scan ${detail.id.slice(0, 8)} (${detail.kind})`} wide>
          <dl className="grid grid-cols-3 gap-2 text-sm mb-3">
            <dt className="text-subtle">State</dt><dd className="col-span-2">{detail.state}</dd>
            <dt className="text-subtle">Verdict</dt><dd className="col-span-2">{detail.verdict ?? "—"}</dd>
            <dt className="text-subtle">Submitted</dt><dd className="col-span-2">{new Date(detail.created_at).toLocaleString()}</dd>
            {detail.completed_at && (<>
              <dt className="text-subtle">Completed</dt><dd className="col-span-2">{new Date(detail.completed_at).toLocaleString()}</dd>
            </>)}
            {detail.error && (<>
              <dt className="text-subtle">Error</dt><dd className="col-span-2 text-danger break-all">{detail.error}</dd>
            </>)}
          </dl>
          <h3 className="text-sm font-semibold mb-1">Result</h3>
          <pre className="text-xs bg-muted p-3 rounded overflow-auto max-h-80">
            {JSON.stringify(detail.result ?? {}, null, 2)}
          </pre>
        </Modal>
      )}

      {showSubmit && (
        <Modal
          open
          onClose={() => setShowSubmit(false)}
          title="Submit QR scan"
          footer={
            <>
              <Button variant="secondary" onClick={() => setShowSubmit(false)} disabled={submitting}>Cancel</Button>
              <Button onClick={submitImage} disabled={!imageFile || submitting}>
                {submitting ? "Submitting…" : "Submit"}
              </Button>
            </>
          }
        >
          <Field label="Image with QR code" hint="PNG/JPG/GIF. Decoded URL will be checked against URLhaus.">
            <div
              onDragOver={(event) => {
                event.preventDefault();
                event.stopPropagation();
              }}
              onDrop={handleImageDrop}
              className="rounded border border-dashed border-border bg-muted/40 p-4"
            >
              <input
                type="file"
                accept="image/png,image/jpeg,image/gif,image/bmp,image/webp"
                onChange={(e) => selectImage(e.target.files?.[0] ?? null)}
                className="block text-sm"
              />
              <div className="mt-2 text-sm text-subtle">
                {imageFile ? imageFile.name : "Drop an image here or choose a file."}
              </div>
            </div>
          </Field>
          {submitErr && <div role="alert" className="text-sm text-danger mt-2">{submitErr}</div>}
        </Modal>
      )}
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
}: {
  label: string;
  value: number | undefined;
  loading: boolean;
  tone?: "success" | "warning" | "danger" | "accent";
  total?: number;
  hint: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
      </CardHeader>
      <CardBody>
        <StatTile label={label} value={value} loading={loading} tone={tone} total={total} hint={hint} showLabel={false} />
      </CardBody>
    </Card>
  );
}

function countRows<T>(rows: T[], keyFor: (row: T) => string): ChartRow[] {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const key = keyFor(row) || "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].map(([key, count]) => ({ key, count }));
}

function summarise(j: ScanJob): string {
  if (j.state === "queued") return "waiting for worker";
  if (j.state === "running") return "scanning…";
  if (j.state === "failed") return j.error ?? "failed";
  const r = (j.result ?? {}) as Record<string, unknown>;
  const hits = (r["feed_hits"] as string[] | undefined) ?? [];
  const urls = (r["urls"] as string[] | undefined) ?? [];
  if (hits.length > 0) return `${hits.length} URL(s) matched URLhaus`;
  if (urls.length > 0) return `${urls.length} URL(s) extracted, no feed hit`;
  const decoded = (r["decoded"] as unknown[] | undefined) ?? [];
  if (decoded.length > 0) return `${decoded.length} QR/barcode, no URL`;
  return "no QR / barcode";
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      // result is "data:image/png;base64,...." — strip prefix
      const s = String(reader.result ?? "");
      const comma = s.indexOf(",");
      resolve(comma >= 0 ? s.slice(comma + 1) : s);
    };
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsDataURL(file);
  });
}
