import { cloneElement, Fragment, isValidElement, ReactNode, useId } from "react";
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
  const generatedId = useId();
  const labelId = `${generatedId}-label`;
  const descriptionId = hint || error ? `${generatedId}-description` : undefined;
  const child = isValidElement<Record<string, unknown>>(children) && children.type !== Fragment
    ? cloneElement(children, {
        "aria-labelledby": children.props["aria-label"] || children.props["aria-labelledby"]
          ? children.props["aria-labelledby"]
          : labelId,
        "aria-describedby": children.props["aria-describedby"] ?? descriptionId,
        "aria-required": children.props["aria-required"] ?? (required || undefined),
      })
    : (
      <div
        role="group"
        aria-labelledby={labelId}
        aria-describedby={descriptionId}
        aria-required={required || undefined}
      >
        {children}
      </div>
    );

  return (
    <div className="block text-sm">
      <span className="mb-1 inline-flex items-center gap-2 font-medium">
        <span id={labelId}>
          {label}
          {required && <span aria-hidden="true" className="text-danger"> *</span>}
        </span>
        {help && <HelpTooltip text={help} />}
      </span>
      {child}
      {hint && !error && <span id={descriptionId} className="block mt-1 text-xs text-subtle">{hint}</span>}
      {error && <span id={descriptionId} role="alert" className="block mt-1 text-xs text-danger">{error}</span>}
    </div>
  );
}
