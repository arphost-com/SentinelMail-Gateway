import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ApiError, api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { DataTable, ColumnDef } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface Domain {
  id: string;
  organization_id: string;
  name: string;
  is_active: boolean;
  created_at: string;
}

interface Org {
  id: string;
  name: string;
}

interface DomainForm {
  organization_id: string;
  name: string;
  is_active: boolean;
}

export function DomainsPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [editing, setEditing] = useState<Domain | null>(null);
  const [creating, setCreating] = useState(false);

  const list = useQuery({
    queryKey: ["domains"],
    queryFn: () => api.get<ListResponse<Domain>>("/domains?limit=200"),
  });
  const orgs = useQuery({
    queryKey: ["orgs", "for-select"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=500"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/domains/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }),
  });

  const orgName = (id: string) => orgs.data?.items.find((o) => o.id === id)?.name ?? id.slice(0, 8);

  const columns: ColumnDef<Domain>[] = [
    { key: "name", header: "Domain", sortValue: (d) => d.name, render: (d) => <strong>{d.name}</strong> },
    { key: "org", header: "Organization", sortValue: (d) => orgName(d.organization_id), render: (d) => orgName(d.organization_id) },
    { key: "active", header: "Active", sortValue: (d) => d.is_active, render: (d) => (d.is_active ? "yes" : "no") },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Domains</h1>
        <Button onClick={() => setCreating(true)}>+ New domain</Button>
      </div>

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        rowKey={(d) => d.id}
        empty="No domains configured."
        actions={(d) => (
          <>
            <Button size="sm" variant="secondary" onClick={() => navigate(`/domain-verification?domain=${d.id}`)}>Verify</Button>{" "}
            <Button size="sm" variant="secondary" onClick={() => setEditing(d)}>Edit</Button>{" "}
            <Button
              size="sm"
              variant="danger"
              disabled={remove.isPending}
              onClick={() => confirmDanger(`Delete ${d.name}?`) && remove.mutate(d.id)}
            >
              Delete
            </Button>
          </>
        )}
      />

      {creating && (
        <DomainModal
          title="New domain"
          orgs={orgs.data?.items ?? []}
          initial={{ organization_id: orgs.data?.items?.[0]?.id ?? "", name: "", is_active: true }}
          onClose={() => setCreating(false)}
          onSubmit={async (v) => {
            await api.post("/domains", v);
            qc.invalidateQueries({ queryKey: ["domains"] });
            setCreating(false);
          }}
        />
      )}

      {editing && (
        <DomainModal
          title={`Edit ${editing.name}`}
          orgs={orgs.data?.items ?? []}
          orgFixed
          initial={{ organization_id: editing.organization_id, name: editing.name, is_active: editing.is_active }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            await api.patch(`/domains/${editing.id}`, { name: v.name, is_active: v.is_active });
            qc.invalidateQueries({ queryKey: ["domains"] });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

function DomainModal({
  title,
  orgs,
  initial,
  orgFixed,
  onClose,
  onSubmit,
}: {
  title: string;
  orgs: Org[];
  initial: DomainForm;
  orgFixed?: boolean;
  onClose: () => void;
  onSubmit: (v: DomainForm) => Promise<void>;
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
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Domain name" required>
          <Input
            type="text"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value.trim().toLowerCase() })}
            placeholder="example.com"
            required
          />
        </Field>
        <Field label="Organization" required>
          <select
            disabled={orgFixed}
            value={form.organization_id}
            onChange={(e) => setForm({ ...form, organization_id: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>{o.name}</option>
            ))}
          </select>
        </Field>
        <Field label="Active">
          <label className="inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
            />
            <span className="text-sm">Domain accepts mail</span>
          </label>
        </Field>
        {err && <div role="alert" className="text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}
