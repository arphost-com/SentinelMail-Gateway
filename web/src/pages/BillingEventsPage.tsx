import { useQuery } from "@tanstack/react-query";
import { api, ListResponse } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";

interface BillingEvent {
  id: string;
  provider: string;
  event_type?: string;
  external_id?: string;
  signature_valid: boolean;
  received_at: string;
}

export function BillingEventsPage() {
  const events = useQuery({
    queryKey: ["billing-events"],
    queryFn: () => api.get<ListResponse<BillingEvent>>("/billing/events?limit=100"),
    refetchInterval: 30_000,
  });

  const columns: ColumnDef<BillingEvent>[] = [
    { key: "received", header: "Received", className: "whitespace-nowrap", sortValue: (e) => e.received_at, render: (e) => new Date(e.received_at).toLocaleString() },
    { key: "provider", header: "Provider", sortValue: (e) => e.provider, render: (e) => <span className="font-mono text-xs">{e.provider}</span> },
    { key: "type", header: "Event", sortValue: (e) => e.event_type ?? "unknown", render: (e) => e.event_type ?? <span className="text-subtle">unknown</span> },
    { key: "external", header: "External ID", sortValue: (e) => e.external_id ?? "none", render: (e) => e.external_id ?? <span className="text-subtle">none</span> },
    { key: "sig", header: "Signature", sortValue: (e) => e.signature_valid, render: (e) => e.signature_valid ? "valid" : "invalid" },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-1">Billing hooks</h1>
      <p className="text-sm text-subtle mb-4">
        Signed billing webhook events captured for provider automation.
      </p>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Webhook endpoint</CardTitle>
        </CardHeader>
        <CardBody className="text-sm">
          <code>/api/v1/billing-webhooks/:provider</code>
          <p className="text-subtle mt-2">
            Requires <code>X-SMG-Signature</code> as hex HMAC-SHA256 over the JSON body and
            <code> billing.webhooks_enabled</code> turned on in System settings.
          </p>
        </CardBody>
      </Card>

      {events.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {events.error instanceof Error ? events.error.message : "Failed to load billing events"}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={events.data?.items}
        loading={events.isLoading}
        empty="No billing webhook events captured."
        rowKey={(e) => e.id}
        initialSortDirection="desc"
      />
    </div>
  );
}
