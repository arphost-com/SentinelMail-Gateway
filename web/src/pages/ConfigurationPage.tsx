import { ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "../auth/AuthProvider";
import { Role, roleAtLeast } from "../auth/roles";

interface ConfigurationTab {
  to: string;
  label: string;
  minRole?: Role;
}

const TABS: ConfigurationTab[] = [
  { to: "/configuration/settings", label: "User settings" },
  { to: "/configuration/sender-lists", label: "Allow/block lists" },
  { to: "/configuration/organizations", label: "Organizations", minRole: "msp_admin" },
  { to: "/configuration/domains", label: "Domains", minRole: "org_admin" },
  { to: "/configuration/gateways", label: "Gateways", minRole: "org_admin" },
  { to: "/configuration/policies", label: "Policies", minRole: "org_admin" },
  { to: "/configuration/users", label: "Users", minRole: "org_admin" },
  { to: "/configuration/domain-verification", label: "Domain verification", minRole: "org_admin" },
  { to: "/configuration/org-settings", label: "Org settings", minRole: "org_admin" },
  { to: "/configuration/msp-settings", label: "MSP settings", minRole: "msp_admin" },
  { to: "/configuration/billing-events", label: "Billing hooks", minRole: "super_admin" },
  { to: "/configuration/cluster-status", label: "Cluster status", minRole: "super_admin" },
  { to: "/configuration/system-settings", label: "System settings", minRole: "super_admin" },
  { to: "/configuration/docs", label: "Docs" },
];

export function ConfigurationPage() {
  const { me } = useAuth();
  const tabs = TABS.filter((tab) => !tab.minRole || roleAtLeast(me?.role, tab.minRole));

  return (
    <div>
      <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-semibold mb-1">Configuration</h1>
          <p className="text-sm text-subtle">Manage account preferences, organizations, mail domains, policies, users, and platform settings.</p>
        </div>
      </div>
      <nav aria-label="Configuration tabs" className="mb-4 flex flex-wrap gap-2 border-b border-border">
        {tabs.map((tab) => (
          <TabLink key={tab.to} to={tab.to}>
            {tab.label}
          </TabLink>
        ))}
      </nav>
      <Outlet />
    </div>
  );
}

function TabLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        clsx(
          "border-b-2 px-3 py-2 text-sm font-medium transition-colors",
          isActive
            ? "border-accent text-fg"
            : "border-transparent text-subtle hover:border-border hover:text-fg"
        )
      }
    >
      {children}
    </NavLink>
  );
}
