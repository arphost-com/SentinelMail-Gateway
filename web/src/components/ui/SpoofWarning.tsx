export interface SpoofWarningData {
  auth_status?: string;
  spoof_warning?: string;
  spoof_signals?: string[];
}

export function SpoofBadge({ item }: { item: SpoofWarningData }) {
  if (!item.spoof_warning) return null;
  return (
    <span
      className="inline-flex whitespace-nowrap rounded border border-danger/50 bg-danger/10 px-2 py-0.5 text-xs font-medium text-danger"
      title={item.spoof_warning}
    >
      Possible spoof
    </span>
  );
}

export function SpoofWarning({ item }: { item: SpoofWarningData }) {
  if (!item.spoof_warning) return null;
  return (
    <div role="alert" className="rounded border border-danger/50 bg-danger/10 p-3 text-sm">
      <div className="font-medium text-danger">Possible spoofed email</div>
      <p className="mt-1">{item.spoof_warning}</p>
      {(item.spoof_signals ?? []).length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2" aria-label="Sender authentication signals">
          {item.spoof_signals?.map((signal) => (
            <span key={signal} className="rounded bg-surface px-2 py-0.5 text-xs">{signal}</span>
          ))}
        </div>
      )}
    </div>
  );
}
