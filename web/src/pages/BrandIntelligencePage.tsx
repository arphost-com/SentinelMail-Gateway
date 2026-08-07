import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";

interface BrandEvidence {
  source: string;
  observation_count: number;
  source_rank?: number;
  last_seen?: string;
}

interface BrandItem {
  slug: string;
  name: string;
  aliases: string[];
  official_domains: string[];
  cues: string[];
  protected: boolean;
  priority: number;
  active: boolean;
  evidence: BrandEvidence[];
  manually_reviewed_at?: string;
  updated_at: string;
}

interface BrandSource {
  feed: string;
  enabled: boolean;
  refresh_seconds: number;
  has_api_key: boolean;
  last_refresh_at?: string;
  last_refresh_ok?: boolean;
  last_refresh_err?: string;
  observed_brands: number;
  refreshing: boolean;
}

interface BrandResponse {
  items: BrandItem[];
  total: number;
  limit: number;
  offset: number;
  sources: BrandSource[];
}

interface BrandAuditItem {
  action: string;
  actor_user_id?: string;
  detail?: Record<string, unknown>;
  created_at: string;
}

interface BrandAuditResponse {
  items: BrandAuditItem[];
}

const columns: ColumnDef<BrandItem>[] = [
  {
    key: "name",
    header: "Brand",
    sortable: true,
    sortValue: (brand) => brand.name,
    render: (brand) => (
      <div>
        <div className="font-medium">{brand.name}</div>
        <div className="text-xs text-subtle">{brand.aliases.join(", ")}</div>
      </div>
    ),
  },
  {
    key: "official_domains",
    header: "Official domains",
    sortValue: (brand) => brand.official_domains.join(","),
    render: (brand) => <span className="break-all">{brand.official_domains.join(", ") || "Not validated"}</span>,
  },
  {
    key: "priority",
    header: "Priority",
    sortable: true,
    sortValue: (brand) => brand.priority,
    render: (brand) => brand.priority.toLocaleString(),
  },
  {
    key: "protected",
    header: "Detection",
    sortable: true,
    sortValue: (brand) => brand.protected && brand.active,
    render: (brand) => brand.protected && brand.active ? "Protected" : brand.active ? "Observed only" : "Inactive",
  },
  {
    key: "evidence",
    header: "Sources",
    sortValue: (brand) => brand.evidence.map((item) => item.source).join(","),
    render: (brand) => brand.evidence.map((item) => item.source).join(", ") || "Built in",
  },
];

export function BrandIntelligencePage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(20);
  const [editing, setEditing] = useState<BrandItem | null>(null);
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (search.trim()) params.set("q", search.trim());
  const brands = useQuery({
    queryKey: ["brand-intelligence", search, offset, limit],
    queryFn: () => api.get<BrandResponse>(`/brand-intelligence?${params.toString()}`),
    refetchInterval: (query) => query.state.data?.sources.some((source) => source.refreshing) ? 3_000 : 30_000,
  });
  const refresh = useMutation({
    mutationFn: () => api.post<{ status: string }>("/brand-intelligence/refresh"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["brand-intelligence"] }),
  });
  const canManage = me?.role === "super_admin";

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="mb-1 text-xl font-semibold">Phishing brand intelligence</h1>
          <p className="text-sm text-subtle">
            Validated aliases and official domains used by inbound impersonation detection. Feed-only observations remain inactive until reviewed.
          </p>
        </div>
        {canManage && (
          <Button
            variant="secondary"
            disabled={refresh.isPending || brands.data?.sources.some((source) => source.refreshing)}
            onClick={() => refresh.mutate()}
            title="Download and rank the current verified PhishTank target feed without delaying mail processing"
          >
            {brands.data?.sources.some((source) => source.refreshing) ? "Refresh running…" : "Refresh PhishTank"}
          </Button>
        )}
      </div>

      {refresh.error && (
        <div role="alert" className="mb-3 text-sm text-danger">{refresh.error.message}</div>
      )}

      <div className="mb-4 grid gap-3 md:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Catalog</CardTitle></CardHeader>
          <CardBody>
            <div className="text-2xl font-semibold tabular-nums">{brands.data?.total.toLocaleString() ?? "—"}</div>
            <div className="text-xs text-subtle">stored brands</div>
          </CardBody>
        </Card>
        {(brands.data?.sources ?? []).map((source) => (
          <Card key={source.feed}>
            <CardHeader><CardTitle>{source.feed}</CardTitle></CardHeader>
            <CardBody className="grid gap-1 text-sm">
              <div>{source.enabled ? "Enabled" : "Disabled"} · {source.observed_brands.toLocaleString()} observed brands</div>
              <div className="text-xs text-subtle">
                {source.refreshing
                  ? "Manual refresh in progress"
                  : source.last_refresh_at
                    ? `${source.last_refresh_ok ? "Healthy" : "Refresh failed"} · ${new Date(source.last_refresh_at).toLocaleString()}`
                    : source.has_api_key ? "Waiting for first refresh" : "Application key not configured"}
              </div>
              {source.last_refresh_err && !source.refreshing && <div role="alert" className="text-xs text-danger">{source.last_refresh_err}</div>}
            </CardBody>
          </Card>
        ))}
      </div>

      <label className="mb-3 block max-w-xl text-sm font-medium">
        Search brands, aliases, or official domains
        <Input
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
          placeholder="Spotify, Microsoft, spotify.com…"
          className="mt-1"
        />
      </label>

      {brands.error && (
        <div role="alert" className="mb-3 text-sm text-danger">
          {brands.error instanceof Error ? brands.error.message : "Failed to load phishing-brand intelligence"}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={brands.data?.items}
        loading={brands.isLoading}
        empty={brands.isLoading ? "Loading brand intelligence…" : "No matching brands."}
        rowKey={(brand) => brand.slug}
        actions={canManage ? (brand) => (
          <Button variant="secondary" size="sm" onClick={() => setEditing(brand)}>
            Review
          </Button>
        ) : undefined}
        manualPagination={{
          total: brands.data?.total ?? 0,
          offset,
          pageSize: limit,
          onOffsetChange: setOffset,
          onPageSizeChange: setLimit,
        }}
      />

      <BrandEditor
        brand={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          void qc.invalidateQueries({ queryKey: ["brand-intelligence"] });
        }}
      />
    </div>
  );
}

function BrandEditor({
  brand,
  onClose,
  onSaved,
}: {
  brand: BrandItem | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [aliases, setAliases] = useState("");
  const [domains, setDomains] = useState("");
  const [cues, setCues] = useState("");
  const [priority, setPriority] = useState(0);
  const [protectedBrand, setProtectedBrand] = useState(false);
  const [active, setActive] = useState(true);

  useEffect(() => {
    if (!brand) return;
    setName(brand.name);
    setAliases(brand.aliases.join("\n"));
    setDomains(brand.official_domains.join("\n"));
    setCues(brand.cues.join("\n"));
    setPriority(brand.priority);
    setProtectedBrand(brand.protected);
    setActive(brand.active);
  }, [brand]);

  const history = useQuery({
    queryKey: ["brand-intelligence-history", brand?.slug],
    queryFn: () => api.get<BrandAuditResponse>(`/brand-intelligence/${brand?.slug}/history`),
    enabled: Boolean(brand),
  });
  const save = useMutation({
    mutationFn: () => api.patch<BrandItem>(`/brand-intelligence/${brand?.slug}`, {
      name,
      aliases: splitValues(aliases),
      official_domains: splitValues(domains),
      cues: splitValues(cues),
      priority,
      protected: protectedBrand,
      active,
    }),
    onSuccess: onSaved,
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  return (
    <Modal
      open={Boolean(brand)}
      onClose={onClose}
      title={brand ? `Review ${brand.name}` : "Review brand"}
      wide
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" form="brand-intelligence-editor" disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save reviewed brand"}
          </Button>
        </>
      )}
    >
      {brand && (
        <form id="brand-intelligence-editor" className="grid gap-4" onSubmit={submit}>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Brand name" required>
              <Input value={name} maxLength={128} onChange={(event) => setName(event.target.value)} />
            </Field>
            <Field label="Priority" hint="0–10000; higher values are evaluated first">
              <Input type="number" min={0} max={10_000} value={priority} onChange={(event) => setPriority(Number(event.target.value))} />
            </Field>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <MultilineField label="Aliases" value={aliases} onChange={setAliases} hint="One phishing-visible brand phrase per line" />
            <MultilineField label="Official domains" value={domains} onChange={setDomains} hint="Validated domains only; no URLs or wildcards" />
            <MultilineField label="Security cues" value={cues} onChange={setCues} hint="Account, payment, login, delivery, or similar context" />
          </div>
          <div className="flex flex-wrap gap-5">
            <label className="inline-flex items-center gap-2 text-sm">
              <input type="checkbox" checked={protectedBrand} onChange={(event) => setProtectedBrand(event.target.checked)} />
              Use in impersonation detection
            </label>
            <label className="inline-flex items-center gap-2 text-sm">
              <input type="checkbox" checked={active} onChange={(event) => setActive(event.target.checked)} />
              Active
            </label>
          </div>
          {save.error && <div role="alert" className="text-sm text-danger">{save.error.message}</div>}
          <section aria-labelledby="brand-history-title">
            <h3 id="brand-history-title" className="mb-2 text-sm font-semibold">Review history</h3>
            {history.isLoading && <div className="text-sm text-subtle">Loading history…</div>}
            {!history.isLoading && (history.data?.items.length ?? 0) === 0 && (
              <div className="text-sm text-subtle">No manual changes have been recorded.</div>
            )}
            <ol className="grid gap-2">
              {(history.data?.items ?? []).map((item, index) => (
                <li key={`${item.created_at}-${index}`} className="rounded border border-border px-3 py-2 text-sm">
                  <div className="font-medium">{item.action}</div>
                  <div className="text-xs text-subtle">
                    {new Date(item.created_at).toLocaleString()}
                    {item.actor_user_id ? ` · actor ${item.actor_user_id}` : ""}
                  </div>
                </li>
              ))}
            </ol>
          </section>
        </form>
      )}
    </Modal>
  );
}

function MultilineField({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint: string;
}) {
  return (
    <Field label={label} hint={hint}>
      <textarea
        rows={8}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="block w-full rounded border border-border bg-surface px-3 py-2 text-sm text-fg focus:border-accent"
      />
    </Field>
  );
}

function splitValues(value: string): string[] {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}
