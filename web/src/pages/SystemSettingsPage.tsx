import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { SchemaSettingsForm } from "../components/SchemaSettingsForm";
import { ThreatFeedsTab } from "./settings/ThreatFeedsTab";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";

const GROUP_LABELS = {
  ui: "Branding",
  mail: "Mail plane",
  retention: "Retention",
  quarantine: "Quarantine",
  ai: "AI analysis",
  threat_intel: "Threat intelligence",
  tls: "TLS / HTTPS",
  billing: "Billing hooks",
  cluster: "Gateway node",
};

/**
 * /system-settings — super_admin only. Catalogues all SYSTEM-WIDE
 * (organization_id IS NULL) configuration: branding, mail-plane,
 * quarantine defaults, TLS, and the threat-feed registry.
 *
 * Per-org overrides live on /org-settings.
 */
export function SystemSettingsPage() {
  const health = useQuery({
    queryKey: ["system-health"],
    queryFn: () => api.get<{ status: string; checks: Record<string, string> }>("/healthz"),
    refetchInterval: 30_000,
  });
  return (
    <div>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold">System settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-subtle">
          Global defaults for every organization. Organization-specific overrides belong in Org settings.
        </p>
      </div>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>System health</CardTitle>
        </CardHeader>
        <CardBody>
          {health.error && <div role="alert" className="text-sm text-danger">{health.error.message}</div>}
          <dl className="grid gap-2 text-sm md:grid-cols-[10rem_1fr]">
            {Object.entries(health.data?.checks ?? {}).map(([name, status]) => (
              <div key={name} className="contents">
                <dt className="font-medium uppercase">{name}</dt>
                <dd className={status === "ok" ? "text-success" : status.startsWith("error") ? "text-danger" : "text-warning"}>
                  {status}
                </dd>
              </div>
            ))}
          </dl>
          {!health.data && !health.error && <div className="text-sm text-subtle">Checking system health…</div>}
        </CardBody>
      </Card>

      <Card className="mb-4">
        <CardHeader className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle>Global configuration</CardTitle>
            <p className="text-xs text-subtle">Working controls for branding, mail plane, AI providers, retention, quarantine, TLS, billing webhooks, and node identity.</p>
          </div>
        </CardHeader>
        <CardBody>
          <SchemaSettingsForm
            endpoint="/system/settings"
            queryKey="system-settings"
            groupLabels={GROUP_LABELS}
          />
          <p className="mt-3 rounded border border-border bg-muted px-3 py-2 text-xs text-subtle">
            <strong>TLS</strong> changes are persisted immediately but the
            Caddy front-end picks them up on its next start. After flipping
            <code> tls.mode</code> from <code>off</code> to <code>self_signed</code>
            or <code>lets_encrypt</code>, restart the <code>caddy</code> container
            (or wait for the next deploy).
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle>Threat feeds</CardTitle>
            <p className="text-xs text-subtle">Provider status, refresh intervals, API keys, and enablement.</p>
          </div>
        </CardHeader>
        <CardBody>
          <ThreatFeedsTab />
        </CardBody>
      </Card>
    </div>
  );
}
