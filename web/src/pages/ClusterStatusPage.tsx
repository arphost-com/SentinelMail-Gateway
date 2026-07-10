import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { StatTile } from "../components/ui/Charts";
import { ColumnDef, DataTable } from "../components/ui/DataTable";

interface ClusterNode {
  id: string;
  hostname: string;
  version: string;
  last_seen_at: string;
}

interface ClusterStatus {
  mode: string;
  local_id: string;
  hostname: string;
  version: string;
  checked_at: string;
  nodes: ClusterNode[];
}

export function ClusterStatusPage() {
  const status = useQuery({
    queryKey: ["cluster-status"],
    queryFn: () => api.get<ClusterStatus>("/cluster/status"),
    refetchInterval: 30_000,
  });
  const data = status.data;

  const columns: ColumnDef<ClusterNode>[] = [
    { key: "id", header: "Node ID", sortValue: (n) => n.id, render: (n) => <span className="font-mono text-xs">{n.id}</span> },
    { key: "host", header: "Hostname", sortValue: (n) => n.hostname, render: (n) => n.hostname },
    { key: "version", header: "Version", render: (n) => n.version || "unknown" },
    { key: "seen", header: "Last seen", className: "whitespace-nowrap", sortValue: (n) => n.last_seen_at, render: (n) => new Date(n.last_seen_at).toLocaleString() },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-1">Cluster status</h1>
      <p className="text-sm text-subtle mb-4">
        Node heartbeat view for single-node and future multi-node deployments.
      </p>

      {status.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {status.error instanceof Error ? status.error.message : "Failed to load cluster status"}
        </div>
      )}

      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-4 mb-4">
        <Metric label="Mode" value={data?.mode ?? "loading"} hint="deployment topology" />
        <Metric label="Known nodes" count={data?.nodes.length} loading={status.isLoading} tone={data?.nodes.length ? "success" : "warning"} hint="heartbeat records" />
        <Metric label="Local node" value={data?.local_id ?? "loading"} hint="active API instance" mono />
        <Metric label="Hostname" value={data?.hostname ?? "loading"} hint="reported by node" />
      </div>

      <DataTable
        columns={columns}
        rows={data?.nodes}
        loading={status.isLoading}
        empty="No node heartbeats recorded."
        rowKey={(n) => n.id}
      />
    </div>
  );
}

function Metric({
  label,
  value,
  count,
  loading,
  tone,
  hint,
  mono,
}: {
  label: string;
  value?: string;
  count?: number;
  loading?: boolean;
  tone?: "success" | "warning" | "danger" | "accent";
  hint: string;
  mono?: boolean;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
      </CardHeader>
      <CardBody>
        {typeof count === "number" || loading ? (
          <StatTile label={label} value={count} loading={Boolean(loading)} tone={tone} hint={hint} showLabel={false} />
        ) : (
          <>
            <div className={`text-lg font-semibold truncate ${mono ? "font-mono text-sm" : ""}`} title={value}>
              {value}
            </div>
            <div className="mt-1 text-xs text-subtle">{hint}</div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
