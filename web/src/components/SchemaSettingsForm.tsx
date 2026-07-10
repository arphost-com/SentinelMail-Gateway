import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "./ui/Card";
import { Field } from "./ui/Field";
import { Input } from "./ui/Input";

interface SettingMeta {
  key: string;
  label: string;
  description: string;
  kind: "string" | "int" | "bool" | "enum";
  options?: string[];
  group: string;
  min?: number;
  max?: number;
}

interface Setting {
  key: string;
  value: unknown;
  updated_at: string;
}

interface SettingsResp {
  items: Setting[];
  schema: SettingMeta[];
}

interface Props {
  // API path under /api/v1 (e.g. "/system/settings" or "/org-settings").
  endpoint: string;
  // Cache key for react-query — different per scope so the two forms don't collide.
  queryKey: string;
  // Optional override of the form heading group; defaults to capitalised group.
  groupLabels?: Record<string, string>;
}

/**
 * Schema-driven settings form. Reads /<endpoint> to get {items, schema} and
 * renders one Card per group, with a single Save button at the bottom that
 * PATCHes only the keys the user changed. Adding a new key on the backend
 * makes it appear here automatically the next time the page loads.
 */
export function SchemaSettingsForm({ endpoint, queryKey, groupLabels }: Props) {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: [queryKey],
    queryFn: () => api.get<SettingsResp>(endpoint),
  });

  const [form, setForm] = useState<Record<string, unknown>>({});
  const [dirty, setDirty] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!data) return;
    const next: Record<string, unknown> = {};
    for (const s of data.items) next[s.key] = s.value;
    setForm(next);
    setDirty({});
  }, [data]);

  const grouped = useMemo(() => {
    if (!data) return [];
    const by: Record<string, SettingMeta[]> = {};
    for (const m of data.schema) (by[m.group] ??= []).push(m);
    return Object.entries(by);
  }, [data]);
  const dirtyCount = Object.keys(dirty).length;

  const save = useMutation({
    mutationFn: (patch: Record<string, unknown>) => api.patch<SettingsResp>(endpoint, patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [queryKey] });
      setDirty({});
      setErr(null);
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : String(e)),
  });

  function update(key: string, value: unknown) {
    setForm((f) => ({ ...f, [key]: value }));
    setDirty((d) => ({ ...d, [key]: true }));
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    const patch: Record<string, unknown> = {};
    for (const k of Object.keys(dirty)) patch[k] = form[k];
    if (Object.keys(patch).length === 0) return;
    save.mutate(patch);
  }

  if (isLoading) return <div className="text-sm text-subtle">Loading…</div>;
  if (error) return <div role="alert" className="text-sm text-danger">{error instanceof Error ? error.message : "Failed to load"}</div>;
  if (!data) return null;

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="rounded border border-border bg-muted/60 p-3">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold">Setting groups</div>
            <div className="text-xs text-subtle">
              {data.schema.length} keys across {grouped.length} groups
              {dirtyCount > 0 && <span> - {dirtyCount} unsaved</span>}
            </div>
          </div>
          <Button type="submit" size="sm" disabled={dirtyCount === 0 || save.isPending}>
            {save.isPending ? "Saving..." : dirtyCount ? `Save ${dirtyCount}` : "Saved"}
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {grouped.map(([group, metas]) => {
            const changed = metas.filter((m) => dirty[m.key]).length;
            return (
              <a
                key={group}
                href={`#settings-${slugify(group)}`}
                className="inline-flex items-center gap-2 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-fg hover:bg-muted hover:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              >
                <span>{groupLabels?.[group] ?? group}</span>
                <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-subtle">
                  {changed > 0 ? `${changed}/${metas.length}` : metas.length}
                </span>
              </a>
            );
          })}
        </div>
      </div>

      {grouped.map(([group, metas]) => (
        <Card key={group} id={`settings-${slugify(group)}`} className="scroll-mt-6">
          <CardHeader className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle className={groupLabels?.[group] ? "" : "capitalize"}>
                {groupLabels?.[group] ?? group}
              </CardTitle>
              <p className="text-xs text-subtle">{metas.length} settings</p>
            </div>
            {metas.some((m) => dirty[m.key]) && (
              <span className="w-fit rounded bg-warning/15 px-2 py-1 text-xs font-medium text-warning">
                Unsaved changes
              </span>
            )}
          </CardHeader>
          <CardBody className="grid gap-3 grid-cols-1 md:grid-cols-2">
            {metas.map((m) => (
              <div
                key={m.key}
                className={dirty[m.key] ? "rounded border border-warning/70 bg-warning/10 p-2" : "rounded border border-transparent p-2"}
              >
                <Field label={m.label} hint={m.description}>
                  <Control meta={m} value={form[m.key]} onChange={(v) => update(m.key, v)} />
                </Field>
              </div>
            ))}
          </CardBody>
        </Card>
      ))}

      {err && <div role="alert" className="text-sm text-danger mb-2">{err}</div>}

      <div className="sticky bottom-0 z-10 flex flex-wrap items-center justify-between gap-3 rounded border border-border bg-bg/95 px-4 py-3 shadow-sm backdrop-blur">
        <span className="text-sm text-subtle">
          {dirtyCount === 0 ? "All settings are saved." : `${dirtyCount} setting${dirtyCount === 1 ? "" : "s"} changed.`}
        </span>
        <Button type="submit" disabled={dirtyCount === 0 || save.isPending}>
          {save.isPending
            ? "Saving…"
            : `Save changes${dirtyCount ? ` (${dirtyCount})` : ""}`}
        </Button>
      </div>
    </form>
  );
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "group";
}

function Control({
  meta,
  value,
  onChange,
}: {
  meta: SettingMeta;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  switch (meta.kind) {
    case "bool":
      return (
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
          enabled
        </label>
      );
    case "int":
      return (
        <Input
          type="number"
          min={meta.min}
          max={meta.max}
          value={typeof value === "number" ? value : 0}
          onChange={(e) => onChange(Number(e.target.value))}
        />
      );
    case "enum":
      return (
        <select
          value={typeof value === "string" ? value : meta.options?.[0] ?? ""}
          onChange={(e) => onChange(e.target.value)}
          className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
        >
          {meta.options?.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      );
    case "string":
    default:
      return (
        <Input
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(e.target.value)}
        />
      );
  }
}
