import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppLayout } from "./layouts/AppLayout";
import { useAuth } from "./auth/AuthProvider";
import { Role, roleAtLeast } from "./auth/roles";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { QuarantinePage } from "./pages/QuarantinePage";
import { SettingsPage } from "./pages/SettingsPage";
import { OrganizationsPage } from "./pages/OrganizationsPage";
import { DomainsPage } from "./pages/DomainsPage";
import { GatewaysPage } from "./pages/GatewaysPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { SenderListsPage } from "./pages/SenderListsPage";
import { UsersPage } from "./pages/UsersPage";
import { ThreatsPage } from "./pages/ThreatsPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import { DocsPage } from "./pages/DocsPage";
import { MailLogsPage } from "./pages/MailLogsPage";
import { SmtpEventsPage } from "./pages/SmtpEventsPage";
import { MailboxPage } from "./pages/MailboxPage";
import { SystemSettingsPage } from "./pages/SystemSettingsPage";
import { OrgSettingsPage } from "./pages/OrgSettingsPage";
import { MspSettingsPage } from "./pages/MspSettingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ReportingLogsPage } from "./pages/ReportingLogsPage";
import { SentEmailsPage } from "./pages/SentEmailsPage";
import { ConfigurationPage } from "./pages/ConfigurationPage";
import { DomainVerificationPage } from "./pages/DomainVerificationPage";
import { BillingEventsPage } from "./pages/BillingEventsPage";
import { ClusterStatusPage } from "./pages/ClusterStatusPage";
import { Card, CardBody, CardHeader, CardTitle } from "./components/ui/Card";

function RequireAuth({ children }: { children: JSX.Element }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-subtle text-sm" role="status" aria-live="polite">
        Loading…
      </div>
    );
  }
  if (!me) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}

/**
 * RequireRole gates a route on a minimum role. If the user's role is below
 * the requirement we render an inline "not available" notice rather than
 * silently redirecting — that way a typed-URL forbidden has a visible
 * reason instead of looking like the link is broken.
 */
function RequireRole({ minRole, children }: { minRole: Role; children: JSX.Element }) {
  const { me } = useAuth();
  if (!roleAtLeast(me?.role, minRole)) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Not available for your role</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-sm">
            This screen requires the <code>{minRole}</code> role or higher. Your role is{" "}
            <code>{me?.role}</code>. Ask an administrator if you need access.
          </p>
        </CardBody>
      </Card>
    );
  }
  return children;
}

function RedirectPreserveSearch({ to }: { to: string }) {
  const location = useLocation();
  return <Navigate to={{ pathname: to, search: location.search }} replace />;
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        {/* Everyone (org_user+) */}
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/mailbox" element={<MailboxPage />} />
        <Route path="/mail-logs" element={<RedirectPreserveSearch to="/reports/mail-logs" />} />
        <Route path="/quarantine" element={<QuarantinePage />} />
        <Route path="/threats" element={<RedirectPreserveSearch to="/reports/threats" />} />
        <Route path="/audit-log" element={<RedirectPreserveSearch to="/reports/audit-log" />} />
        <Route path="/settings" element={<RedirectPreserveSearch to="/configuration/settings" />} />
        <Route path="/docs" element={<RedirectPreserveSearch to="/configuration/docs" />} />
        <Route path="/configuration" element={<ConfigurationPage />}>
          <Route index element={<RedirectPreserveSearch to="/configuration/settings" />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="sender-lists" element={<SenderListsPage />} />
          <Route path="organizations" element={<RequireRole minRole="msp_admin"><OrganizationsPage /></RequireRole>} />
          <Route path="domains" element={<RequireRole minRole="org_admin"><DomainsPage /></RequireRole>} />
          <Route path="gateways" element={<RequireRole minRole="org_admin"><GatewaysPage /></RequireRole>} />
          <Route path="policies" element={<RequireRole minRole="org_admin"><PoliciesPage /></RequireRole>} />
          <Route path="users" element={<RequireRole minRole="org_admin"><UsersPage /></RequireRole>} />
          <Route path="domain-verification" element={<RequireRole minRole="org_admin"><DomainVerificationPage /></RequireRole>} />
          <Route path="org-settings" element={<RequireRole minRole="org_admin"><OrgSettingsPage /></RequireRole>} />
          <Route path="msp-settings" element={<RequireRole minRole="msp_admin"><MspSettingsPage /></RequireRole>} />
          <Route path="billing-events" element={<RequireRole minRole="super_admin"><BillingEventsPage /></RequireRole>} />
          <Route path="cluster-status" element={<RequireRole minRole="super_admin"><ClusterStatusPage /></RequireRole>} />
          <Route path="system-settings" element={<RequireRole minRole="super_admin"><SystemSettingsPage /></RequireRole>} />
          <Route path="docs" element={<DocsPage />} />
        </Route>

        {/* org_admin+ */}
        <Route path="/domains" element={<RedirectPreserveSearch to="/configuration/domains" />} />
        <Route path="/gateways" element={<RedirectPreserveSearch to="/configuration/gateways" />} />
        <Route path="/policies" element={<RedirectPreserveSearch to="/configuration/policies" />} />
        <Route path="/sender-lists" element={<RedirectPreserveSearch to="/configuration/sender-lists" />} />
        <Route path="/users" element={<RedirectPreserveSearch to="/configuration/users" />} />
        <Route path="/reports" element={<RequireRole minRole="org_admin"><ReportingLogsPage><ReportsPage /></ReportingLogsPage></RequireRole>} />
        <Route path="/reports/threats" element={<ReportingLogsPage><ThreatsPage /></ReportingLogsPage>} />
        <Route path="/reports/mail-logs" element={<ReportingLogsPage><MailLogsPage /></ReportingLogsPage>} />
        <Route path="/reports/audit-log" element={<ReportingLogsPage><AuditLogPage /></ReportingLogsPage>} />
        <Route path="/reports/smtp-events" element={<RequireRole minRole="org_admin"><ReportingLogsPage><SmtpEventsPage /></ReportingLogsPage></RequireRole>} />
        <Route path="/reports/sent-emails" element={<RequireRole minRole="org_admin"><ReportingLogsPage><SentEmailsPage /></ReportingLogsPage></RequireRole>} />
        <Route path="/smtp-events" element={<RedirectPreserveSearch to="/reports/smtp-events" />} />
        <Route path="/sent-emails" element={<RedirectPreserveSearch to="/reports/sent-emails" />} />
        <Route path="/domain-verification" element={<RedirectPreserveSearch to="/configuration/domain-verification" />} />
        <Route path="/org-settings" element={<RedirectPreserveSearch to="/configuration/org-settings" />} />

        {/* msp_admin+ */}
        <Route path="/organizations" element={<RedirectPreserveSearch to="/configuration/organizations" />} />
        <Route path="/msp-settings" element={<RedirectPreserveSearch to="/configuration/msp-settings" />} />

        {/* super_admin only */}
        <Route path="/billing-events" element={<RedirectPreserveSearch to="/configuration/billing-events" />} />
        <Route path="/cluster-status" element={<RedirectPreserveSearch to="/configuration/cluster-status" />} />
        <Route path="/system-settings" element={<RedirectPreserveSearch to="/configuration/system-settings" />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
