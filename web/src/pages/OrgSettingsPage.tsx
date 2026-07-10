import { SchemaSettingsForm } from "../components/SchemaSettingsForm";

const GROUP_LABELS = {
  brand: "Branding",
  alerts: "Alerts",
  retention: "Retention",
  quarantine: "Quarantine",
  digest: "End-user digest",
  billing: "Billing",
};

/**
 * /org-settings — org_admin (or higher) within their own organization.
 * Schema-driven from /api/v1/org-settings (which reads
 * system_settings rows scoped to ident.OrganizationID).
 */
export function OrgSettingsPage() {
  return (
    <div>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold">Organization settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-subtle">
          Tenant-specific overrides for branding, alerts, retention, quarantine, digest email, and billing.
          Values here take precedence for messages and users in this organization.
        </p>
      </div>

      <SchemaSettingsForm
        endpoint="/org-settings"
        queryKey="org-settings"
        groupLabels={GROUP_LABELS}
      />
    </div>
  );
}
