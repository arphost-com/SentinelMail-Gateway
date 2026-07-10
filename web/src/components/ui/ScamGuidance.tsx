interface ScamLink {
  label: string;
  url: string;
}

export interface ScamGuidanceData {
  scam_warning?: string;
  scam_signals?: string[];
  scam_links?: ScamLink[];
}

export function ScamGuidance({ item }: { item: ScamGuidanceData }) {
  if (!item.scam_warning) return null;
  const links = (item.scam_links ?? []).filter((link) => isTrustedSource(link.url));
  return (
    <div role="alert" className="rounded border border-warning bg-warning/10 p-3 text-sm">
      <div className="font-medium text-warning">Common scam pattern found</div>
      <p className="mt-1">{item.scam_warning}</p>
      {item.scam_signals && item.scam_signals.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2" aria-label="Matched scam signals">
          {item.scam_signals.map((signal) => (
            <span key={signal} className="rounded bg-muted px-2 py-0.5 text-xs">{signal}</span>
          ))}
        </div>
      )}
      {links.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2" aria-label="Related scam education links">
          {links.map((link) => (
            <a
              key={link.url}
              href={link.url}
              target="_blank"
              rel="noreferrer"
              className="rounded border border-border bg-surface px-2 py-1 text-xs underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-focus"
            >
              {link.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function isTrustedSource(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && TRUSTED_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

const TRUSTED_HOSTS = new Set([
  "www.cisa.gov",
  "consumer.ftc.gov",
  "www.ftc.gov",
  "www.fbi.gov",
  "www.ic3.gov",
]);
