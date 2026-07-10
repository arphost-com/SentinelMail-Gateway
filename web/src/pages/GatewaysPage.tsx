import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { DataTable, ColumnDef } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { HelpTooltip } from "../components/ui/HelpTooltip";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface Gateway {
  id: string;
  organization_id: string;
  domain_id: string;
  kind: string;
  host: string;
  port: number;
  use_tls: boolean;
  priority: number;
  is_active: boolean;
}

interface Domain {
  id: string;
  name: string;
}

interface Form {
  domain_id: string;
  kind: string;
  host: string;
  port: number;
  use_tls: boolean;
  priority: number;
  is_active: boolean;
}

const KINDS = ["smtp_relay", "mailcow", "postfix", "exchange", "m365", "gws"];

export function GatewaysPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Gateway | null>(null);
  const [creating, setCreating] = useState(false);

  const list = useQuery({
    queryKey: ["gateways"],
    queryFn: () => api.get<ListResponse<Gateway>>("/gateways?limit=200"),
  });
  const domains = useQuery({
    queryKey: ["domains", "for-select"],
    queryFn: () => api.get<ListResponse<Domain>>("/domains?limit=500"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/gateways/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["gateways"] }),
  });

  const domainName = (id: string) => domains.data?.items.find((d) => d.id === id)?.name ?? id.slice(0, 8);

  const columns: ColumnDef<Gateway>[] = [
    { key: "domain", header: "Domain", sortValue: (g) => domainName(g.domain_id), render: (g) => domainName(g.domain_id) },
    { key: "kind", header: "Kind", render: (g) => g.kind },
    { key: "endpoint", header: "Endpoint", sortValue: (g) => `${g.host}:${g.port}`, render: (g) => `${g.host}:${g.port}` },
    { key: "tls", header: "TLS", sortValue: (g) => g.use_tls, render: (g) => (g.use_tls ? "yes" : "no") },
    { key: "prio", header: "Priority", className: "text-right", sortValue: (g) => g.priority, render: (g) => <span className="tabular-nums">{g.priority}</span> },
    { key: "active", header: "Active", sortValue: (g) => g.is_active, render: (g) => (g.is_active ? "yes" : "no") },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Gateways</h1>
        <Button onClick={() => setCreating(true)}>+ New gateway</Button>
      </div>

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        rowKey={(g) => g.id}
        empty="No gateways configured."
        actions={(g) => (
          <>
            <Button size="sm" variant="secondary" onClick={() => setEditing(g)}>Edit</Button>{" "}
            <Button
              size="sm"
              variant="danger"
              disabled={remove.isPending}
              onClick={() => confirmDanger(`Delete gateway ${g.host}:${g.port}?`) && remove.mutate(g.id)}
            >
              Delete
            </Button>
          </>
        )}
      />

      {creating && (
        <GwModal
          title="New gateway"
          domains={domains.data?.items ?? []}
          initial={{
            domain_id: domains.data?.items?.[0]?.id ?? "",
            kind: "smtp_relay",
            host: "",
            port: 25,
            use_tls: true,
            priority: 10,
            is_active: true,
          }}
          onClose={() => setCreating(false)}
          onSubmit={async (v) => {
            await api.post("/gateways", v);
            qc.invalidateQueries({ queryKey: ["gateways"] });
            setCreating(false);
          }}
        />
      )}

      {editing && (
        <GwModal
          title={`Edit ${editing.host}`}
          domains={domains.data?.items ?? []}
          domainFixed
          initial={{
            domain_id: editing.domain_id,
            kind: editing.kind,
            host: editing.host,
            port: editing.port,
            use_tls: editing.use_tls,
            priority: editing.priority,
            is_active: editing.is_active,
          }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            const { domain_id, ...rest } = v;
            void domain_id;
            await api.patch(`/gateways/${editing.id}`, rest);
            qc.invalidateQueries({ queryKey: ["gateways"] });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

function GwModal({
  title,
  domains,
  domainFixed,
  initial,
  onClose,
  onSubmit,
}: {
  title: string;
  domains: Domain[];
  domainFixed?: boolean;
  initial: Form;
  onClose: () => void;
  onSubmit: (v: Form) => Promise<void>;
}) {
  const [form, setForm] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(form);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      wide
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid gap-3 grid-cols-1 md:grid-cols-2">
        <Field label="Domain" required>
          <select
            disabled={domainFixed}
            value={form.domain_id}
            onChange={(e) => setForm({ ...form, domain_id: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {domains.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
        </Field>
        <Field label="Kind" required help="Selects the downstream mail system type. This is used for operator context and future provider-specific checks.">
          <select
            value={form.kind}
            onChange={(e) => setForm({ ...form, kind: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </Field>
        <Field label="Host" required help="Downstream mail server hostname or IP that SentinelMail releases and relays accepted mail to.">
          <Input
            value={form.host}
            onChange={(e) => setForm({ ...form, host: e.target.value.trim() })}
            placeholder="mx.backend.example.com"
            required
          />
        </Field>
        <Field label="Port" required help="SMTP port on the downstream mail server. Port 25 is common for internal relay; 587 is common for authenticated submission.">
          <Input
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 25 })}
            required
          />
        </Field>
        <Field label="Priority" hint="lower = preferred" help="When a domain has multiple active gateways, lower priority values are tried first.">
          <Input
            type="number"
            min={0}
            max={1000}
            value={form.priority}
            onChange={(e) => setForm({ ...form, priority: Number(e.target.value) || 10 })}
          />
        </Field>
        <div className="block text-sm">
          <div className="mb-1 font-medium">Options</div>
          <div className="flex flex-col gap-1">
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.use_tls} onChange={(e) => setForm({ ...form, use_tls: e.target.checked })} />
                <span>Use TLS</span>
              </label>
              <HelpTooltip text="Use SMTP over TLS when connecting to the downstream gateway. Disable only for trusted internal relays that do not support TLS." />
            </div>
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.is_active} onChange={(e) => setForm({ ...form, is_active: e.target.checked })} />
                <span>Active</span>
              </label>
              <HelpTooltip text="Inactive gateways are kept for reference but skipped for delivery and quarantine release routing." />
            </div>
          </div>
        </div>
        {err && <div role="alert" className="md:col-span-2 text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}
