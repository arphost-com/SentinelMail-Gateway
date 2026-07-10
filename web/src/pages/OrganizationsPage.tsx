import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminStats, adminWindowLabel } from "../api/adminStats";
import { ApiError, api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { DataTable, ColumnDef } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface Org {
  id: string;
  name: string;
  slug: string;
  parent_id?: string;
  is_system: boolean;
  is_active: boolean;
  created_at: string;
}

interface OrgForm {
  name: string;
  slug: string;
  parent_id?: string;
}

export function OrganizationsPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Org | null>(null);
  const [creating, setCreating] = useState(false);
  const [statsWindow, setStatsWindow] = useState("7d");

  const list = useQuery({
    queryKey: ["orgs"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=200"),
  });
  const stats = useQuery({
    queryKey: ["admin-stats", statsWindow],
    queryFn: () => api.get<AdminStats>(`/reports/admin-stats?window=${statsWindow}`),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/orgs/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["orgs"] }),
  });

  const orgStats = (id: string) => stats.data?.orgs.find((row) => row.id === id);
  const mspColumns: ColumnDef<AdminStats["msps"][number]>[] = [
    { key: "name", header: "MSP", sortValue: (row) => row.name, render: (row) => <strong>{row.name}</strong> },
    { key: "child_orgs", header: "Orgs", className: "text-right tabular-nums", render: (row) => row.child_orgs },
    { key: "active_users", header: "Users", className: "text-right tabular-nums", render: (row) => row.active_users },
    { key: "domains", header: "Domains", className: "text-right tabular-nums", render: (row) => row.domains },
    { key: "processed", header: "Processed", className: "text-right tabular-nums", render: (row) => row.processed.toLocaleString() },
    { key: "quarantined", header: "Quarantined", className: "text-right tabular-nums", render: (row) => row.quarantined.toLocaleString() },
    { key: "rejected", header: "Rejected", className: "text-right tabular-nums", render: (row) => row.rejected.toLocaleString() },
    { key: "phishing_reports", header: "Phishing", className: "text-right tabular-nums", render: (row) => row.phishing_reports.toLocaleString() },
  ];
  const columns: ColumnDef<Org>[] = [
    { key: "name", header: "Name", render: (o) => o.name },
    { key: "slug", header: "Slug", sortValue: (o) => o.slug, render: (o) => <code className="text-xs">{o.slug}</code> },
    { key: "active", header: "Active", sortValue: (o) => o.is_active, render: (o) => (o.is_active ? "yes" : "no") },
    { key: "system", header: "System", sortValue: (o) => o.is_system, render: (o) => (o.is_system ? "yes" : "") },
    { key: "users", header: "Users", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.active_users ?? 0, render: (o) => orgStats(o.id)?.active_users ?? "—" },
    { key: "domains", header: "Domains", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.domains ?? 0, render: (o) => orgStats(o.id)?.domains ?? "—" },
    { key: "processed", header: "Processed", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.processed ?? 0, render: (o) => orgStats(o.id)?.processed.toLocaleString() ?? "—" },
    { key: "quarantined", header: "Quarantined", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.quarantined ?? 0, render: (o) => orgStats(o.id)?.quarantined.toLocaleString() ?? "—" },
    { key: "phishing", header: "Phishing", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.phishing_reports ?? 0, render: (o) => orgStats(o.id)?.phishing_reports.toLocaleString() ?? "—" },
  ];

  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between mb-4">
        <h1 className="text-2xl font-semibold">Organizations</h1>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="block text-subtle mb-1">Stats window</span>
            <select
              value={statsWindow}
              onChange={(event) => setStatsWindow(event.target.value)}
              className="block rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
            </select>
          </label>
          <Button onClick={() => setCreating(true)}>+ New organization</Button>
        </div>
      </div>

      {list.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          {list.error instanceof Error ? list.error.message : "Failed to load"}
        </div>
      )}

      {stats.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          {stats.error instanceof Error ? stats.error.message : "Failed to load statistics"}
        </div>
      )}

      <div className="mb-4">
        <h2 className="text-lg font-semibold mb-2">MSP statistics ({adminWindowLabel(statsWindow)})</h2>
        <DataTable
          columns={mspColumns}
          rows={stats.data?.msps}
          loading={stats.isLoading}
          empty="No MSP organizations in scope."
          rowKey={(row) => row.id}
        />
      </div>

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        rowKey={(o) => o.id}
        empty="No organizations yet."
        actions={(o) => (
          <>
            <Button size="sm" variant="secondary" onClick={() => setEditing(o)}>Edit</Button>{" "}
            <Button
              size="sm"
              variant="danger"
              disabled={o.is_system || remove.isPending}
              onClick={() => {
                if (confirmDanger(`Delete organization "${o.name}"? This cannot be undone.`)) {
                  remove.mutate(o.id);
                }
              }}
            >
              Delete
            </Button>
          </>
        )}
      />

      {creating && (
        <OrgFormModal
          title="New organization"
          initial={{ name: "", slug: "" }}
          onClose={() => setCreating(false)}
          onSubmit={async (v) => {
            await api.post("/orgs", v);
            qc.invalidateQueries({ queryKey: ["orgs"] });
            setCreating(false);
          }}
        />
      )}

      {editing && (
        <OrgFormModal
          title={`Edit ${editing.name}`}
          initial={{ name: editing.name, slug: editing.slug, parent_id: editing.parent_id }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            await api.patch(`/orgs/${editing.id}`, v);
            qc.invalidateQueries({ queryKey: ["orgs"] });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

function OrgFormModal({
  title,
  initial,
  onClose,
  onSubmit,
}: {
  title: string;
  initial: OrgForm;
  onClose: () => void;
  onSubmit: (v: OrgForm) => Promise<void>;
}) {
  const [form, setForm] = useState<OrgForm>(initial);
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
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Name" required>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </Field>
        <Field label="Slug" required hint="lowercase, digits and hyphens, 3-64 chars">
          <Input
            value={form.slug}
            onChange={(e) => setForm({ ...form, slug: e.target.value })}
            pattern="^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
            required
          />
        </Field>
        {err && <div role="alert" className="text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}
