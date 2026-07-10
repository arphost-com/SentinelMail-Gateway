import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ListResponse } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Button } from "../components/ui/Button";
import { Modal } from "../components/ui/Modal";

interface AuditEntry {
  id: number;
  organization_id?: string;
  actor_user_id?: string;
  actor_ip?: string;
  action: string;
  target_kind?: string;
  target_id?: string;
  detail?: Record<string, unknown>;
  created_at: string;
}

export function AuditLogPage() {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [detail, setDetail] = useState<AuditEntry | null>(null);

  const params = new URLSearchParams();
  if (action) params.set("action", action);
  if (actor) params.set("actor_user_id", actor);
  params.set("limit", "100");

  const list = useQuery({
    queryKey: ["audit-log", action, actor],
    queryFn: () => api.get<ListResponse<AuditEntry>>(`/audit-log?${params.toString()}`),
    refetchInterval: 30_000,
  });

  const cols: ColumnDef<AuditEntry>[] = [
    { key: "when", header: "When", sortValue: (e) => e.created_at, render: (e) => new Date(e.created_at).toLocaleString() },
    { key: "action", header: "Action", sortValue: (e) => e.action, render: (e) => <code className="text-xs">{e.action}</code> },
    { key: "actor", header: "Actor", sortValue: (e) => e.actor_user_id ?? "system", render: (e) => e.actor_user_id ? <span className="font-mono text-xs">{e.actor_user_id.slice(0, 8)}…</span> : <span className="text-subtle">system</span> },
    { key: "ip", header: "IP", sortValue: (e) => e.actor_ip ?? "", render: (e) => <span className="font-mono text-xs">{e.actor_ip ?? "—"}</span> },
    { key: "target", header: "Target", sortValue: (e) => e.target_kind ? `${e.target_kind}${e.target_id ? `/${e.target_id.slice(0, 8)}` : ""}` : "", render: (e) => e.target_kind ? `${e.target_kind}${e.target_id ? `/${e.target_id.slice(0, 8)}` : ""}` : "—" },
    { key: "detail", header: "Detail", sortValue: (e) => e.detail ? JSON.stringify(e.detail) : "", render: (e) => e.detail ? <code className="text-xs text-subtle break-all">{JSON.stringify(e.detail).slice(0, 120)}</code> : "—" },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <Button variant="secondary" size="sm" onClick={() => list.refetch()}>Refresh</Button>
      </div>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Action" hint="e.g. auth.login, user.update">
            <Input value={action} onChange={(e) => setAction(e.target.value.trim())} placeholder="auth.login" />
          </Field>
          <Field label="Actor user_id (UUID)">
            <Input value={actor} onChange={(e) => setActor(e.target.value.trim())} placeholder="abcd1234-…" />
          </Field>
        </CardBody>
      </Card>

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {list.error instanceof Error ? list.error.message : "Failed to load"}
        </div>
      )}

      <DataTable
        columns={cols}
        rows={list.data?.items}
        loading={list.isLoading}
        empty="No audit entries match the current filters."
        rowKey={(e) => String(e.id)}
        initialSortDirection="desc"
        actions={(e) => <Button size="sm" variant="secondary" onClick={() => setDetail(e)}>Details</Button>}
      />

      {detail && (
        <Modal open onClose={() => setDetail(null)} title={`Audit event ${detail.id}`} wide>
          <dl className="mb-4 grid grid-cols-3 gap-2 text-sm">
            <dt className="text-subtle">When</dt>
            <dd className="col-span-2">{new Date(detail.created_at).toLocaleString()}</dd>
            <dt className="text-subtle">Action</dt>
            <dd className="col-span-2"><code>{detail.action}</code></dd>
            <dt className="text-subtle">Actor</dt>
            <dd className="col-span-2 font-mono text-xs break-all">{detail.actor_user_id ?? "system"}</dd>
            <dt className="text-subtle">IP</dt>
            <dd className="col-span-2 font-mono text-xs">{detail.actor_ip ?? "—"}</dd>
            <dt className="text-subtle">Organization</dt>
            <dd className="col-span-2 font-mono text-xs break-all">{detail.organization_id ?? "—"}</dd>
            <dt className="text-subtle">Target</dt>
            <dd className="col-span-2 font-mono text-xs break-all">
              {detail.target_kind ?? "—"}{detail.target_id ? ` / ${detail.target_id}` : ""}
            </dd>
          </dl>
          <h3 className="mb-2 text-sm font-semibold">Detail JSON</h3>
          <pre className="max-h-[32rem] overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap">
            {JSON.stringify(detail.detail ?? {}, null, 2)}
          </pre>
        </Modal>
      )}
    </div>
  );
}
