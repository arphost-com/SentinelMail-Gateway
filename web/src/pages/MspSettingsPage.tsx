import { FormEvent, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { AdminStats, adminWindowLabel } from "../api/adminStats";
import { ApiError, api, ListResponse } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { StatTile } from "../components/ui/Charts";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";

interface Org {
  id: string;
  name: string;
  slug: string;
  parent_id?: string;
  is_system: boolean;
  is_active: boolean;
  created_at: string;
}

/**
 * /msp-settings — msp_admin (or higher). Lists child organizations
 * (orgs whose parent_id is the caller's org) and lets the MSP admin
 * provision new ones. Uses /api/v1/orgs which is already tenant-scoped
 * so msp_admin only sees their own subtree.
 */
export function MspSettingsPage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [statsWindow, setStatsWindow] = useState("7d");

  const list = useQuery({
    queryKey: ["orgs", "msp"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=200"),
  });
  const stats = useQuery({
    queryKey: ["admin-stats", statsWindow],
    queryFn: () => api.get<AdminStats>(`/reports/admin-stats?window=${statsWindow}`),
  });

  // "Children" = everything except the MSP's own org row.
  const children = (list.data?.items ?? []).filter((o) => o.id !== me?.organization_id);
  const ownOrg = (list.data?.items ?? []).find((o) => o.id === me?.organization_id);
  const ownStats = stats.data?.msps.find((row) => row.id === me?.organization_id);
  const orgStats = (id: string) => stats.data?.orgs.find((row) => row.id === id);

  const columns: ColumnDef<Org>[] = [
    { key: "name", header: "Name", render: (o) => o.name },
    { key: "slug", header: "Slug", sortValue: (o) => o.slug, render: (o) => <code className="text-xs">{o.slug}</code> },
    { key: "active", header: "Active", sortValue: (o) => o.is_active, render: (o) => (o.is_active ? "yes" : "no") },
    {
      key: "created",
      header: "Created",
      sortValue: (o) => o.created_at,
      render: (o) => new Date(o.created_at).toLocaleDateString(),
    },
    { key: "users", header: "Users", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.active_users ?? 0, render: (o) => orgStats(o.id)?.active_users ?? "—" },
    { key: "domains", header: "Domains", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.domains ?? 0, render: (o) => orgStats(o.id)?.domains ?? "—" },
    { key: "processed", header: "Processed", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.processed ?? 0, render: (o) => orgStats(o.id)?.processed.toLocaleString() ?? "—" },
    { key: "quarantined", header: "Quarantined", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.quarantined ?? 0, render: (o) => orgStats(o.id)?.quarantined.toLocaleString() ?? "—" },
    { key: "phishing", header: "Phishing", className: "text-right tabular-nums", sortValue: (o) => orgStats(o.id)?.phishing_reports ?? 0, render: (o) => orgStats(o.id)?.phishing_reports.toLocaleString() ?? "—" },
  ];

  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold">MSP settings</h1>
          {ownOrg && (
            <p className="text-sm text-subtle">
              Your MSP organization: <strong>{ownOrg.name}</strong> (<code>{ownOrg.slug}</code>)
            </p>
          )}
        </div>
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
          <Button onClick={() => setCreating(true)}>+ New customer org</Button>
        </div>
      </div>

      {stats.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          {stats.error instanceof Error ? stats.error.message : "Failed to load MSP statistics"}
        </div>
      )}

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-4 mb-4">
        <StatCard label="Processed" value={ownStats?.processed} loading={stats.isLoading} hint={adminWindowLabel(statsWindow)} />
        <StatCard label="Customers" value={ownStats?.child_orgs ?? children.length} loading={stats.isLoading && !ownStats} hint="direct child organizations" />
        <StatCard label="Quarantined" value={ownStats?.quarantined} loading={stats.isLoading} tone="warning" hint="held mail" />
        <StatCard label="Phishing" value={ownStats?.phishing_reports} loading={stats.isLoading} tone="danger" hint="confirmed reports" />
      </div>

      <div className="mb-4">
        <h2 className="text-lg font-semibold mb-2">Customer organizations ({children.length})</h2>
        <DataTable
          columns={columns}
          rows={children}
          loading={list.isLoading || stats.isLoading}
          empty="No customer organizations yet. Create one to get started."
          rowKey={(o) => o.id}
          actions={() => (
            <Link to="/configuration/organizations" className="text-sm underline">
              Manage in Organizations
            </Link>
          )}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Tips</CardTitle>
        </CardHeader>
        <CardBody className="text-sm text-subtle space-y-1">
          <p>
            • New customer orgs inherit your MSP's policies until they're customised at the org or
            domain level (Configuration → <strong>Policies</strong>).
          </p>
          <p>
            • Each customer's <strong>org_admin</strong> can manage their own Domains, Gateways and
            Users without seeing other customers.
          </p>
          <p>
            • You retain visibility across the entire tree via Configuration tabs for Domains / Gateways /
            Quarantine / Users pages — the tenant scope walks the org parent chain.
          </p>
        </CardBody>
      </Card>

      {creating && (
        <NewOrgModal
          parentId={me?.organization_id ?? ""}
          onClose={() => setCreating(false)}
          onCreated={() => {
            qc.invalidateQueries({ queryKey: ["orgs", "msp"] });
            qc.invalidateQueries({ queryKey: ["orgs"] });
            setCreating(false);
          }}
        />
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  loading,
  tone,
  hint,
}: {
  label: string;
  value?: number;
  loading?: boolean;
  tone?: "success" | "warning" | "danger" | "accent";
  hint: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
      </CardHeader>
      <CardBody>
        <StatTile label={label} value={value} loading={Boolean(loading)} tone={tone} hint={hint} showLabel={false} />
      </CardBody>
    </Card>
  );
}

function NewOrgModal({
  parentId,
  onClose,
  onCreated,
}: {
  parentId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api.post("/orgs", { name, slug, parent_id: parentId });
      onCreated();
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
      title="New customer organization"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Creating…" : "Create"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Name" required>
          <Input value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label="Slug" required hint="lowercase, digits and hyphens, 3-64 chars">
          <Input
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            pattern="^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
            required
          />
        </Field>
        {err && <div role="alert" className="text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}
