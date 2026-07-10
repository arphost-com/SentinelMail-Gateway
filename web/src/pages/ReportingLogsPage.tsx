import { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "../auth/AuthProvider";
import { roleAtLeast } from "../auth/roles";

interface ReportingLogsPageProps {
  children: ReactNode;
}

export function ReportingLogsPage({ children }: ReportingLogsPageProps) {
  const { me } = useAuth();
  const canAdmin = roleAtLeast(me?.role, "org_admin");
  const tabs = [
    ...(canAdmin ? [{ to: "/reports", label: "Reports", end: true }] : []),
    { to: "/reports/threats", label: "Threats" },
    { to: "/reports/mail-logs", label: "Mail logs" },
    ...(canAdmin ? [{ to: "/reports/sent-emails", label: "Sent emails" }] : []),
    { to: "/reports/audit-log", label: "Audit logs" },
    ...(canAdmin ? [{ to: "/reports/smtp-events", label: "SMTP Events" }] : []),
  ];

  return (
    <div>
      <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-semibold mb-1">Reporting and logs</h1>
          <p className="text-sm text-subtle">Review message history, operator activity, SMTP events, and report summaries.</p>
        </div>
      </div>
      <nav aria-label="Reporting and logs tabs" className="mb-4 flex flex-wrap gap-2 border-b border-border">
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              clsx(
                "border-b-2 px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "border-accent text-fg"
                  : "border-transparent text-subtle hover:border-border hover:text-fg"
              )
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>
      {children}
    </div>
  );
}
