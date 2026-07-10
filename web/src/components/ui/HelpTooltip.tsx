import { useId, useState } from "react";

export function HelpTooltip({ text }: { text: string }) {
  const id = useId();
  const [open, setOpen] = useState(false);

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border bg-muted text-xs font-semibold text-fg shadow-sm hover:border-accent hover:text-accent focus:outline-none focus:ring-2 focus:ring-focus"
        aria-label="Show help"
        aria-describedby={open ? id : undefined}
        aria-expanded={open}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onMouseDown={(event) => event.preventDefault()}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          setOpen((value) => !value);
        }}
      >
        ?
      </button>
      {open && (
        <span
          id={id}
          role="tooltip"
          className="absolute left-1/2 top-full z-50 mt-2 w-72 max-w-[min(18rem,calc(100vw-2rem))] -translate-x-1/2 rounded-md border border-border bg-surface px-3 py-2 text-left text-xs font-normal leading-relaxed text-fg shadow-xl"
        >
          {text}
        </span>
      )}
    </span>
  );
}
