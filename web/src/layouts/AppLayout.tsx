import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "../auth/AuthProvider";
import { Role, roleAtLeast } from "../auth/roles";
import { Button } from "../components/ui/Button";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { api } from "../api/client";

interface NavItem {
  to: string;
  label: string;
  minRole?: Role; // default = org_user (everyone)
  activePrefix?: string;
}

const NAV_SECTIONS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Monitor",
    items: [
      { to: "/dashboard", label: "Dashboard" },
      { to: "/mailbox", label: "Mailbox" },
      { to: "/quarantine", label: "Quarantine" },
      { to: "/reports/mail-logs", label: "Reporting and logs", activePrefix: "/reports" },
      { to: "/configuration/settings", label: "Configuration", activePrefix: "/configuration" },
    ],
  },
];

export function AppLayout() {
  const { me, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const visibleSections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => !item.minRole || roleAtLeast(me?.role, item.minRole)),
  })).filter((section) => section.items.length > 0);

  async function stopImpersonating() {
    try {
      await api.post("/auth/impersonate/stop");
    } finally {
      window.location.assign("/");
    }
  }

  return (
    <div className="min-h-full">
      <a href="#main" className="skip-link">
        Skip to main content
      </a>
      {me?.impersonating && (
        <div
          role="status"
          className="flex items-center justify-between gap-3 border-b border-warning bg-warning/15 px-4 py-2 text-sm text-fg"
        >
          <span>
            Impersonating <strong>{me.email}</strong> — signed in as {me.impersonator_email ?? "an administrator"}.
          </span>
          <Button size="sm" variant="secondary" onClick={stopImpersonating}>
            Stop impersonating
          </Button>
        </div>
      )}
      <div className="grid min-h-screen max-w-full grid-cols-1 overflow-hidden lg:grid-cols-[15rem_minmax(0,1fr)]">
        <aside
          aria-label="Primary"
          className="flex flex-col border-b border-border bg-surface p-3 lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:border-b-0 lg:border-r lg:p-4"
        >
          <div className="mb-3 flex items-center gap-2 border-b border-border px-2 pb-3">
            <img src="/favicon.svg" alt="" width={28} height={28} className="shrink-0" />
            <div>
              <div className="text-sm font-semibold tracking-wide leading-tight">SentinelMail</div>
              <div className="text-[10px] text-subtle tracking-widest uppercase">Gateway</div>
            </div>
          </div>
          <nav aria-label="Sections" className="flex gap-4 overflow-x-auto pb-1 text-sm lg:flex-col lg:gap-4 lg:overflow-visible lg:pb-0">
            {visibleSections.map((section) => (
              <div key={section.label} className="min-w-[11rem] lg:min-w-0">
                <div className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-widest text-subtle">
                  {section.label}
                </div>
                <div className="flex flex-col gap-1">
                  {section.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === "/dashboard"}
                      className={({ isActive }) => {
                        const active = isActive || (item.activePrefix ? location.pathname.startsWith(item.activePrefix) : false);
                        return clsx(
                          "rounded px-3 py-2 transition-colors",
                          active ? "bg-accent text-accentFg shadow-sm" : "text-fg hover:bg-muted"
                        );
                      }}
                    >
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
            <Button
              variant="secondary"
              size="sm"
              className="mt-5 w-full shrink-0 lg:mt-1"
              onClick={async () => {
                await logout();
                navigate("/login", { replace: true });
              }}
            >
              Sign out
            </Button>
            <div className="mt-2 border-t border-border pt-2 text-xs text-subtle">
              <NavLink
                to="/configuration/settings"
                className={({ isActive }) =>
                  clsx(
                    "block rounded px-3 py-2 transition-colors",
                    isActive ? "bg-accent text-accentFg shadow-sm" : "text-fg hover:bg-muted"
                  )
                }
                title={me ? `${me.email} / ${formatRole(me.role)}` : undefined}
              >
                <span className="block truncate">{me?.email}</span>
                <span className="block text-[10px] uppercase tracking-wider opacity-80">{formatRole(me?.role)}</span>
              </NavLink>
            </div>
          </nav>
        </aside>
        <main id="main" className="min-w-0 overflow-auto p-4 lg:p-6">
          {/* Reset the boundary on navigation so a fixed bug doesn't leave
              the error card stuck visible after the user moves on. */}
          <ErrorBoundary resetKey={location.pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

function formatRole(role?: string) {
  return role ? role.split("_").map((part) => part.toUpperCase()).join("_") : "";
}
