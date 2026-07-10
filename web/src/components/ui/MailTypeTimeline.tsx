export interface TimeTypeRow {
  bucket: string;
  type: string;
  count: number;
}

const TYPE_COLORS = [
  "rgb(var(--chart-1))",
  "rgb(var(--chart-2))",
  "rgb(var(--chart-3))",
  "rgb(var(--chart-4))",
  "rgb(var(--chart-5))",
  "rgb(var(--chart-6))",
  "rgb(var(--chart-7))",
  "rgb(var(--chart-8))",
];

const STREAM_WIDTH = 720;
const STREAM_HEIGHT = 180;
const STREAM_PAD_X = 18;
const STREAM_PAD_Y = 12;

export function MailTypeTimeline({
  rows,
  empty = "No mail type data for this window.",
  compact,
  bucketFormat = "day",
  selectedBucket,
  onBucketSelect,
}: {
  rows: TimeTypeRow[];
  empty?: string;
  compact?: boolean;
  bucketFormat?: "hour" | "day";
  selectedBucket?: string;
  onBucketSelect?: (bucket: TimelineBucketSelection) => void;
}) {
  const prepared = prepareTimeline(rows, bucketFormat);
  const total = prepared.totals.reduce((sum, row) => sum + row.count, 0);
  const selected = prepared.buckets.find((bucket) => bucket.key === selectedBucket);
  if (prepared.buckets.length === 0) {
    return <div className="text-sm text-subtle">{empty}</div>;
  }
  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-2">
        {prepared.totals.map((row) => (
          <div key={row.type} className="inline-flex items-center gap-2 rounded border border-border bg-muted/40 px-2.5 py-1 text-xs">
            <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ backgroundColor: prepared.colorFor(row.type) }} />
            <span className="max-w-[12rem] truncate">{row.type}</span>
            <span className="font-medium tabular-nums">{row.count}</span>
          </div>
        ))}
      </div>
      <div
        className="rounded border border-border bg-muted/20 px-3 pb-3 pt-4"
        role="img"
        aria-label="Stream graph of mail types over time"
      >
        <div className="min-w-0">
          <div className="min-w-0">
            <svg
              className="block h-56 w-full overflow-visible"
              viewBox={`0 0 ${STREAM_WIDTH} ${STREAM_HEIGHT + 42}`}
              preserveAspectRatio="none"
              aria-hidden="true"
            >
              <rect x="0" y="0" width={STREAM_WIDTH} height={STREAM_HEIGHT} rx="10" className="fill-surface/70" />
              {[0.25, 0.5, 0.75].map((line) => (
                <line
                  key={line}
                  x1={STREAM_PAD_X}
                  x2={STREAM_WIDTH - STREAM_PAD_X}
                  y1={STREAM_HEIGHT * line}
                  y2={STREAM_HEIGHT * line}
                  className="stroke-border/70"
                  strokeDasharray="4 6"
                />
              ))}
              <line
                x1={STREAM_PAD_X}
                x2={STREAM_WIDTH - STREAM_PAD_X}
                y1={STREAM_HEIGHT / 2}
                y2={STREAM_HEIGHT / 2}
                className="stroke-border"
              />
              {prepared.streamLayers.map((layer, i) => (
                <path
                  key={layer.type}
                  d={layer.path}
                  fill={prepared.colorFor(layer.type)}
                  fillOpacity={i === 0 ? 0.9 : 0.78}
                  stroke="rgb(var(--surface))"
                  strokeWidth="1.5"
                >
                  <title>{`${layer.type}: ${layer.total.toLocaleString()} messages`}</title>
                </path>
              ))}
              {prepared.buckets.map((bucket, i) => {
                const showLabel = shouldShowBucketLabel(i, prepared.buckets.length, compact);
                const nextX = prepared.buckets[i + 1]?.x ?? STREAM_WIDTH - STREAM_PAD_X;
                const prevX = prepared.buckets[i - 1]?.x ?? STREAM_PAD_X;
                const hitX = i === 0 ? STREAM_PAD_X : (prevX + bucket.x) / 2;
                const hitWidth = i === prepared.buckets.length - 1 ? STREAM_WIDTH - STREAM_PAD_X - hitX : (bucket.x + nextX) / 2 - hitX;
                const isSelected = selectedBucket === bucket.key;
                return (
                  <g
                    key={bucket.key}
                    role={onBucketSelect ? "button" : undefined}
                    tabIndex={onBucketSelect ? 0 : undefined}
                    className={onBucketSelect ? "cursor-pointer focus:outline-none" : undefined}
                    aria-label={`${bucket.label}: ${bucket.total.toLocaleString()} messages`}
                    onClick={() => onBucketSelect?.(bucketSelection(bucket))}
                    onKeyDown={(event) => {
                      if (!onBucketSelect) return;
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onBucketSelect(bucketSelection(bucket));
                      }
                    }}
                  >
                    {onBucketSelect && (
                      <rect
                        x={hitX}
                        y="0"
                        width={Math.max(10, hitWidth)}
                        height={STREAM_HEIGHT + 38}
                        fill="transparent"
                      />
                    )}
                    <line
                      x1={bucket.x}
                      x2={bucket.x}
                      y1={STREAM_HEIGHT - STREAM_PAD_Y}
                      y2={STREAM_HEIGHT + 5}
                      className={isSelected ? "stroke-accent" : "stroke-border"}
                      strokeWidth={isSelected ? 2 : 1}
                    />
                    {showLabel && (
                      <text
                        x={bucket.x}
                        y={STREAM_HEIGHT + 20}
                        textAnchor="middle"
                        className={isSelected ? "fill-accent text-[11px] font-semibold" : "fill-subtle text-[11px]"}
                      >
                        {bucket.label}
                      </text>
                    )}
                    {showLabel && (
                      <text
                        x={bucket.x}
                        y={STREAM_HEIGHT + 34}
                        textAnchor="middle"
                        className="fill-fg text-[11px] font-medium"
                      >
                        {bucket.total.toLocaleString()}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      </div>
      {selected && (
        <div className="mt-3 rounded border border-border bg-muted/30 p-3 text-sm" role="status">
          <div className="font-medium">
            {selected.total.toLocaleString()} emails at {selected.label}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {selected.segments.map((segment) => (
              <span key={segment.type} className="rounded bg-surface px-2 py-1 text-xs">
                {segment.type}: <span className="font-medium tabular-nums">{segment.count.toLocaleString()}</span>
              </span>
            ))}
          </div>
        </div>
      )}
      {total > 0 && total < 5 && (
        <div className="mt-3 text-xs text-subtle">
          Small sample. Treat trends as directional until more messages are processed.
        </div>
      )}
      <table className="sr-only">
        <caption>Mail type counts over time</caption>
        <thead>
          <tr><th>Time</th><th>Mail type</th><th>Count</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.bucket}-${row.type}`}>
              <td>{formatBucket(row.bucket, bucketFormat)}</td>
              <td>{row.type}</td>
              <td>{row.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export interface TimelineBucketSelection {
  key: string;
  label: string;
  total: number;
  start: string;
  end: string;
  segments: Array<{ type: string; count: number }>;
}

function prepareTimeline(rows: TimeTypeRow[], bucketFormat: "hour" | "day") {
  const typeTotals = new Map<string, number>();
  for (const row of rows) {
    typeTotals.set(row.type, (typeTotals.get(row.type) ?? 0) + row.count);
  }
  const topTypes = [...typeTotals.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TYPE_COLORS.length - 1)
    .map(([type]) => type);
  const bucketMap = new Map<string, { key: string; label: string; total: number; counts: Map<string, number> }>();
  for (const row of rows) {
    const key = row.bucket;
    const type = topTypes.includes(row.type) ? row.type : "Other";
    const existing = bucketMap.get(key) ?? { key, label: formatBucket(row.bucket, bucketFormat), total: 0, counts: new Map<string, number>() };
    existing.total += row.count;
    existing.counts.set(type, (existing.counts.get(type) ?? 0) + row.count);
    bucketMap.set(key, existing);
  }
  const totals = [...typeTotals.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TYPE_COLORS.length - 1)
    .map(([type, count]) => ({ type, count }));
  const otherTotal = [...typeTotals.entries()].filter(([type]) => !topTypes.includes(type)).reduce((sum, [, count]) => sum + count, 0);
  if (otherTotal > 0) totals.push({ type: "Other", count: otherTotal });
  const buckets = [...bucketMap.values()]
    .sort((a, b) => a.key.localeCompare(b.key))
    .map((bucket, index, list) => ({
      ...bucket,
      segments: [...bucket.counts.entries()].sort((a, b) => b[1] - a[1]).map(([type, count]) => ({ type, count })),
      x: xForBucket(index, list.length),
    }));
  const maxBucketTotal = Math.max(1, ...buckets.map((bucket) => bucket.total));
  const colorFor = (type: string) => {
    const idx = totals.findIndex((row) => row.type === type);
    return TYPE_COLORS[Math.max(0, idx) % TYPE_COLORS.length];
  };
  return {
    buckets,
    totals,
    maxBucketTotal,
    colorFor,
    streamLayers: buildStreamLayers(buckets, totals, maxBucketTotal),
  };
}

function bucketSelection(bucket: { key: string; label: string; total: number; segments: Array<{ type: string; count: number }> }): TimelineBucketSelection {
  const start = new Date(bucket.key);
  const end = new Date(start);
  if (Number.isNaN(start.getTime())) {
    return { key: bucket.key, label: bucket.label, total: bucket.total, start: bucket.key, end: bucket.key, segments: bucket.segments };
  }
  if (bucket.key.includes("T")) {
    end.setHours(end.getHours() + 1);
  } else {
    end.setDate(end.getDate() + 1);
  }
  return { key: bucket.key, label: bucket.label, total: bucket.total, start: start.toISOString(), end: end.toISOString(), segments: bucket.segments };
}

function buildStreamLayers(
  buckets: Array<{ x: number; total: number; counts: Map<string, number> }>,
  totals: Array<{ type: string; count: number }>,
  maxBucketTotal: number,
) {
  const drawableHeight = STREAM_HEIGHT - STREAM_PAD_Y * 2;
  const baselines = buckets.map((bucket) => {
    const totalHeight = (bucket.total / maxBucketTotal) * drawableHeight;
    return (STREAM_HEIGHT - totalHeight) / 2;
  });
  const cursors = [...baselines];
  return totals.map((row) => {
    const upper = buckets.map((bucket, i) => {
      const height = ((bucket.counts.get(row.type) ?? 0) / maxBucketTotal) * drawableHeight;
      const point = { x: bucket.x, y: cursors[i] };
      cursors[i] += height;
      return point;
    });
    const lower = buckets.map((bucket, i) => ({ x: bucket.x, y: cursors[i] }));
    return { type: row.type, total: row.count, path: areaPath(upper, lower) };
  }).filter((layer) => layer.path !== "");
}

function xForBucket(index: number, count: number) {
  if (count <= 1) return STREAM_WIDTH / 2;
  return STREAM_PAD_X + (index / (count - 1)) * (STREAM_WIDTH - STREAM_PAD_X * 2);
}

function areaPath(upper: Array<{ x: number; y: number }>, lower: Array<{ x: number; y: number }>) {
  if (upper.length === 0 || lower.length === 0) return "";
  if (upper.length === 1) {
    const width = 12;
    return `M ${upper[0].x - width} ${upper[0].y} L ${upper[0].x + width} ${upper[0].y} L ${lower[0].x + width} ${lower[0].y} L ${lower[0].x - width} ${lower[0].y} Z`;
  }
  return `${curvePath(upper)} L ${lower[lower.length - 1].x} ${lower[lower.length - 1].y} ${curvePath([...lower].reverse(), false)} Z`;
}

function curvePath(points: Array<{ x: number; y: number }>, move = true) {
  if (points.length === 0) return "";
  const commands = move ? [`M ${points[0].x} ${points[0].y}`] : [];
  for (let i = 1; i < points.length; i += 1) {
    const previous = points[i - 1];
    const current = points[i];
    const midX = (previous.x + current.x) / 2;
    commands.push(`C ${midX} ${previous.y}, ${midX} ${current.y}, ${current.x} ${current.y}`);
  }
  return commands.join(" ");
}

function shouldShowBucketLabel(index: number, count: number, compact?: boolean) {
  if (count <= 8) return true;
  const interval = compact ? Math.ceil(count / 4) : Math.ceil(count / 6);
  return index === 0 || index === count - 1 || index % interval === 0;
}

function formatBucket(value: string, bucketFormat: "hour" | "day") {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (bucketFormat === "hour") {
    return date.toLocaleTimeString([], { hour: "numeric" });
  }
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}
