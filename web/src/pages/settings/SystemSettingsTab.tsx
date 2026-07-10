import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../../api/client";
import { Button } from "../../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../../components/ui/Card";
import { Field } from "../../components/ui/Field";
import { Input } from "../../components/ui/Input";

interface SettingMeta {
  key: string;
  label: string;
  description: string;
  kind: "string" | "int" | "bool" | "enum";
  options?: string[];
  group: string;
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

export function SystemSettingsTab() {
  const qc = useQueryClient();
  const { data, error, isLoading } = useQuery({
    queryKey: ["system-settings"],
    queryFn: () => api.get<SettingsResp>("/system/settings"),
  });

  // Local form state keyed by setting key. Initialised once from data.
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
    for (const m of data.schema) {
      (by[m.group] ??= []).push(m);
    }
    return Object.entries(by);
  }, [data]);

  const save = useMutation({
    mutationFn: (patch: Record<string, unknown>) => api.patch<SettingsResp>("/system/settings", patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["system-settings"] });
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
    <form onSubmit={submit}>
      {grouped.map(([group, metas]) => (
        <Card key={group} className="mb-4">
          <CardHeader>
            <CardTitle className="capitalize">{group}</CardTitle>
          </CardHeader>
          <CardBody className="grid gap-3 grid-cols-1 md:grid-cols-2">
            {metas.map((m) => (
              <Field key={m.key} label={m.label} hint={m.description} help={m.description}>
                <SettingControl meta={m} value={form[m.key]} onChange={(v) => update(m.key, v)} />
              </Field>
            ))}
          </CardBody>
        </Card>
      ))}

      {err && <div role="alert" className="text-sm text-danger mb-2">{err}</div>}

      <div className="flex justify-end gap-2">
        <Button type="submit" disabled={Object.keys(dirty).length === 0 || save.isPending}>
          {save.isPending ? "Saving…" : `Save changes${Object.keys(dirty).length ? ` (${Object.keys(dirty).length})` : ""}`}
        </Button>
      </div>
    </form>
  );
}

function SettingControl({
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
