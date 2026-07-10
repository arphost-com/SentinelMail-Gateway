import { SchemaSettingsForm } from "../components/SchemaSettingsForm";
import { ThreatFeedsTab } from "./settings/ThreatFeedsTab";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";

const GROUP_LABELS = {
  ui: "Branding",
  mail: "Mail plane",
  retention: "Retention",
  quarantine: "Quarantine",
  tls: "TLS / HTTPS",
  link_rewrite: "Link rewriting",
  sso: "SSO",
  billing: "Billing hooks",
  cluster: "Multi-node clustering",
};

/**
 * /system-settings — super_admin only. Catalogues all SYSTEM-WIDE
 * (organization_id IS NULL) configuration: branding, mail-plane,
 * quarantine defaults, TLS, and the threat-feed registry.
 *
 * Per-org overrides live on /org-settings.
 */
export function SystemSettingsPage() {
  return (
    <div>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold">System settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-subtle">
          Global defaults for every organization. Organization-specific overrides belong in Org settings.
        </p>
      </div>

      <Card className="mb-4">
        <CardHeader className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle>Global configuration</CardTitle>
            <p className="text-xs text-subtle">Branding, mail plane, retention, quarantine, TLS, billing, and cluster behavior.</p>
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
