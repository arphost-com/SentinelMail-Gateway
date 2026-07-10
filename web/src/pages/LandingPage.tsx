import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";

const services = [
  {
    title: "Managed SaaS gateway",
    summary: "Hosted filtering for teams that want SentinelMail operated, updated, monitored, and scaled for them.",
    points: ["Managed threat feeds", "Tenant administration", "Quarantine and mailbox review", "Operational monitoring"],
  },
  {
    title: "Self-hosted mail filter",
    summary: "Deploy SentinelMail in front of Mailcow, Postfix, Exchange, Microsoft 365, Google Workspace, or a generic SMTP host.",
    points: ["Docker Compose deployment", "Local data control", "Rspamd and ClamAV mail plane", "Per-organization policies"],
  },
];

const signals = [
  ["SPF/DKIM/DMARC", "validated"],
  ["Rspamd score", "7.8"],
  ["URLhaus", "miss"],
  ["Policy action", "tag"],
];

export function LandingPage() {
  const { me } = useAuth();
  const appHref = me ? "/dashboard" : "/login";

  return (
    <main className="min-h-screen bg-bg text-fg">
      <header className="border-b border-border bg-surface/95">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <a href="#top" className="flex min-w-0 items-center gap-3 text-fg hover:no-underline">
            <img src="/logo.svg" alt="SentinelMail Gateway" className="h-10 w-auto max-w-[13rem] shrink-0" />
          </a>
          <nav aria-label="Public navigation" className="flex shrink-0 items-center gap-2 text-sm">
            <a
              href="#services"
              className="rounded px-3 py-2 text-fg hover:bg-muted hover:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
            >
              Services
            </a>
            <Link
              to={appHref}
              className="rounded border border-border bg-accent px-3 py-2 font-medium text-accentFg hover:opacity-90 hover:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
            >
              {me ? "Open dashboard" : "Login"}
            </Link>
          </nav>
        </div>
      </header>

      <section id="top" className="border-b border-border bg-surface">
        <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 sm:px-6 lg:min-h-[34rem] lg:grid-cols-[minmax(0,1fr)_28rem] lg:items-center lg:py-12">
          <div className="min-w-0">
            <p className="mb-3 text-sm font-semibold uppercase tracking-widest text-accent">
              Email security gateway
            </p>
            <h1 className="max-w-3xl text-4xl font-semibold leading-tight sm:text-5xl">
              SentinelMail Gateway
            </h1>
            <p className="mt-4 max-w-2xl text-base leading-7 text-subtle sm:text-lg">
              Hosted SaaS filtering or self-hosted mail protection for organizations that need spam,
              phishing, malware, and policy controls in front of their existing mail server.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link
                to={appHref}
                className="rounded border border-border bg-accent px-4 py-2.5 text-sm font-medium text-accentFg hover:opacity-90 hover:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              >
                {me ? "Open dashboard" : "Login to console"}
              </Link>
              <a
                href="#services"
                className="rounded border border-border bg-muted px-4 py-2.5 text-sm font-medium text-fg hover:bg-border hover:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              >
                View services
              </a>
            </div>
          </div>

          <div className="min-w-0 rounded border border-border bg-bg p-4 shadow-sm" aria-label="Gateway processing preview">
            <div className="mb-4 flex items-center justify-between gap-3 border-b border-border pb-3">
              <div>
                <div className="text-sm font-semibold">Inbound message</div>
                <div className="text-xs text-subtle">invoice-review@example.net</div>
              </div>
              <span className="rounded bg-warning/15 px-2 py-1 text-xs font-medium text-warning">Tagged</span>
            </div>
            <div className="space-y-3">
              {signals.map(([label, value]) => (
                <div key={label} className="flex items-center justify-between gap-3 rounded border border-border bg-surface px-3 py-2 text-sm">
                  <span className="min-w-0 truncate text-subtle">{label}</span>
                  <span className="shrink-0 font-mono text-xs text-fg">{value}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded border border-border bg-surface px-2 py-3">
                <div className="font-semibold text-fg">Deliver</div>
                <div className="mt-1 text-subtle">clean</div>
              </div>
              <div className="rounded border border-border bg-surface px-2 py-3">
                <div className="font-semibold text-fg">Tag</div>
                <div className="mt-1 text-subtle">suspicious</div>
              </div>
              <div className="rounded border border-border bg-surface px-2 py-3">
                <div className="font-semibold text-fg">Hold</div>
                <div className="mt-1 text-subtle">high risk</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="services" className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
        <div className="mb-6 max-w-3xl">
          <h2 className="text-2xl font-semibold">Services offered</h2>
          <p className="mt-2 text-sm leading-6 text-subtle">
            Choose the operating model that fits the customer: fully managed filtering as a service,
            or a self-hosted gateway installed in front of the customer mail environment.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {services.map((service) => (
            <article key={service.title} className="rounded border border-border bg-surface p-5">
              <h3 className="text-lg font-semibold">{service.title}</h3>
              <p className="mt-2 text-sm leading-6 text-subtle">{service.summary}</p>
              <ul className="mt-4 grid gap-2 text-sm">
                {service.points.map((point) => (
                  <li key={point} className="flex gap-2">
                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded bg-success" aria-hidden="true" />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
