import { ReactNode } from "react";
import { HelpTooltip } from "./HelpTooltip";

/**
 * Form field wrapper that pairs a label with its control and surfaces an
 * inline error message. Keeps form pages from re-implementing the same
 * label/error markup five times.
 */
export function Field({
  label,
  hint,
  help,
  error,
  required,
  children,
}: {
  label: ReactNode;
  hint?: string;
  help?: string;
  error?: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <label className="block text-sm">
      <span className="mb-1 inline-flex items-center gap-2 font-medium">
        <span>
          {label}
          {required && <span aria-hidden="true" className="text-danger"> *</span>}
        </span>
        {help && <HelpTooltip text={help} />}
      </span>
      {children}
      {hint && !error && <span className="block mt-1 text-xs text-subtle">{hint}</span>}
      {error && <span role="alert" className="block mt-1 text-xs text-danger">{error}</span>}
    </label>
  );
}
