import clsx from "clsx";
import { ReactNode } from "react";

export interface ChartRow {
  key: string;
  count: number;
}

const CHART_COLORS = [
  "rgb(var(--chart-1))",
  "rgb(var(--chart-2))",
  "rgb(var(--chart-3))",
  "rgb(var(--chart-4))",
  "rgb(var(--chart-5))",
  "rgb(var(--chart-6))",
  "rgb(var(--chart-7))",
  "rgb(var(--chart-8))",
];

export function numberLabel(value: number | undefined) {
  return (value ?? 0).toLocaleString();
}

export function percentLabel(value: number, total: number) {
  if (total <= 0) return "0%";
  return `${Math.round((value / total) * 100)}%`;
}

export function CompositionDonut({
  rows,
  empty,
  label,
  centerLabel = "total",
  maxRows = 7,
  sort = true,
  hrefForRow,
}: {
  rows: ChartRow[];
  empty: string;
  label: string;
  centerLabel?: string;
  maxRows?: number;
  sort?: boolean;
  hrefForRow?: (row: ChartRow) => string | undefined;
}) {
  const prepared = topRows(rows, maxRows, sort);
  const total = prepared.reduce((sum, row) => sum + row.count, 0);
  if (total === 0) {
    return <EmptyChart>{empty}</EmptyChart>;
  }

  let cursor = 0;
  const stops = prepared.map((row, i) => {
    const start = cursor;
    cursor += (row.count / total) * 100;
    return `${CHART_COLORS[i % CHART_COLORS.length]} ${start}% ${cursor}%`;
  });

  return (
    <div>
      <div className="grid min-w-0 items-center gap-5 md:grid-cols-[12rem_minmax(0,1fr)]">
        <div
          className="relative mx-auto h-44 w-44 rounded-full border border-border shadow-inner"
          style={{ background: `conic-gradient(${stops.join(", ")})` }}
          role="img"
          aria-label={`${label}. Total ${total}. ${prepared.map((row) => `${row.key}: ${row.count}`).join(", ")}`}
        >
          <div className="absolute inset-8 flex flex-col items-center justify-center rounded-full border border-border bg-surface text-center">
            <span className="text-2xl font-semibold tabular-nums">{numberLabel(total)}</span>
            <span className="text-xs text-subtle">{centerLabel}</span>
          </div>
        </div>
        <ChartLegend rows={prepared} total={total} hrefForRow={hrefForRow} />
      </div>
      <AccessibleTable label={label} rows={prepared} />
    </div>
  );
}

export function HorizontalBars({
  rows,
  empty,
  label,
  capitalize,
  monospace,
  maxRows = 8,
  showShare = true,
  sort = true,
  hrefForRow,
}: {
  rows: ChartRow[];
  empty: string;
  label: string;
  capitalize?: boolean;
  monospace?: boolean;
  maxRows?: number;
  showShare?: boolean;
  sort?: boolean;
  hrefForRow?: (row: ChartRow) => string | undefined;
}) {
  const prepared = topRows(rows, maxRows, sort);
  const max = Math.max(1, ...prepared.map((row) => row.count));
  const total = prepared.reduce((sum, row) => sum + row.count, 0);
  if (prepared.length === 0) {
    return <EmptyChart>{empty}</EmptyChart>;
  }

  return (
    <div role={hrefForRow ? undefined : "img"} aria-label={`${label}. ${prepared.map((row) => `${row.key}: ${row.count}`).join(", ")}`}>
      <div className="space-y-3">
        {prepared.map((row, i) => (
          <ChartRowShell key={row.key} href={hrefForRow?.(row)} label={`Show ${label}: ${row.key}, ${row.count} messages`} block>
            <div className="mb-1 flex items-center justify-between gap-3 text-sm">
              <span className={clsx("min-w-0 truncate", capitalize && "capitalize", monospace && "font-mono text-xs")}>{row.key}</span>
              <span className="shrink-0 tabular-nums text-fg">
                {numberLabel(row.count)}
                {showShare && total > 0 && <span className="ml-2 text-xs text-subtle">{percentLabel(row.count, total)}</span>}
              </span>
            </div>
            <div className="h-2.5 overflow-hidden rounded bg-muted" aria-hidden="true">
              <div
                className="h-full rounded"
                style={{
                  width: `${Math.max(3, (row.count / max) * 100)}%`,
                  backgroundColor: CHART_COLORS[i % CHART_COLORS.length],
                }}
              />
            </div>
          </ChartRowShell>
        ))}
      </div>
      <AccessibleTable label={label} rows={prepared} />
    </div>
  );
}

export function StatTile({
  label,
  value,
  loading,
  hint,
  tone,
  total,
  showLabel = true,
}: {
  label: string;
  value: number | undefined;
  loading: boolean;
  hint: string;
  tone?: "success" | "warning" | "danger" | "accent";
  total?: number;
  showLabel?: boolean;
}) {
  const current = value ?? 0;
  const share = total && total > 0 ? Math.min(100, (current / total) * 100) : 0;
  const hasTotal = Boolean(total && total > 0);
  return (
    <div className="flex min-h-[5.5rem] min-w-0 flex-1 flex-col justify-between">
      <div className="flex min-h-4 items-start justify-between gap-2">
        {showLabel && <div className="text-sm font-medium text-subtle">{label}</div>}
        <div className={clsx("text-xs tabular-nums text-subtle", !hasTotal && "invisible")}>
          {percentLabel(current, total ?? 0)}
        </div>
      </div>
      <div className={clsx("mt-2 min-w-0 break-words text-3xl font-semibold leading-tight tabular-nums", toneClass(tone))}>
        {loading ? "..." : numberLabel(current)}
      </div>
      <div className="mt-1 min-h-4 min-w-0 truncate text-xs text-subtle">{hint}</div>
      <div className={clsx("mt-3 h-1.5 overflow-hidden rounded bg-muted", !hasTotal && "invisible")} aria-hidden="true">
        <div className={clsx("h-full rounded", fillClass(tone))} style={{ width: `${Math.max(3, share)}%` }} />
      </div>
    </div>
  );
}

function ChartLegend({ rows, total, hrefForRow }: { rows: ChartRow[]; total: number; hrefForRow?: (row: ChartRow) => string | undefined }) {
  return (
    <div className="space-y-2">
      {rows.map((row, i) => (
        <ChartRowShell key={row.key} href={hrefForRow?.(row)} label={`Show ${row.key}, ${row.count} messages`}>
          <span className="inline-flex min-w-0 items-center gap-2">
            <span className="h-3 w-3 shrink-0 rounded-sm" style={{ backgroundColor: CHART_COLORS[i % CHART_COLORS.length] }} />
            <span className="truncate">{row.key}</span>
          </span>
          <span className="shrink-0 tabular-nums">
            {numberLabel(row.count)}
            <span className="ml-2 text-xs text-subtle">{percentLabel(row.count, total)}</span>
          </span>
        </ChartRowShell>
      ))}
    </div>
  );
}

function ChartRowShell({ href, label, children, block }: { href?: string; label: string; children: ReactNode; block?: boolean }) {
  const className = clsx(
    "rounded px-1 py-0.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-focus",
    block ? "block" : "flex items-center justify-between gap-3 text-sm",
  );
  if (!href) {
    return <div className={className}>{children}</div>;
  }
  return (
    <a href={href} className={clsx(className, "hover:bg-muted/70")} aria-label={label}>
      {children}
    </a>
  );
}

function AccessibleTable({ label, rows }: { label: string; rows: ChartRow[] }) {
  return (
    <table className="sr-only">
      <caption>{label}</caption>
      <thead>
        <tr>
          <th>Category</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td>{row.key}</td>
            <td>{row.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EmptyChart({ children }: { children: string }) {
  return (
    <div className="rounded border border-dashed border-border bg-muted/40 px-4 py-8 text-center text-sm text-subtle">
      {children}
    </div>
  );
}

function topRows(rows: ChartRow[], maxRows: number, sort: boolean) {
  const filtered = rows.filter((row) => row.count > 0);
  if (sort) filtered.sort((a, b) => b.count - a.count);
  if (filtered.length <= maxRows) return filtered;
  const visible = filtered.slice(0, maxRows - 1);
  const other = filtered.slice(maxRows - 1).reduce((sum, row) => sum + row.count, 0);
  return [...visible, { key: "Other", count: other }];
}

function toneClass(tone?: "success" | "warning" | "danger" | "accent") {
  if (tone === "success") return "text-success";
  if (tone === "warning") return "text-warning";
  if (tone === "danger") return "text-danger";
  if (tone === "accent") return "text-accent";
  return "";
}

function fillClass(tone?: "success" | "warning" | "danger" | "accent") {
  if (tone === "success") return "bg-success";
  if (tone === "warning") return "bg-warning";
  if (tone === "danger") return "bg-danger";
  return "bg-accent";
}
