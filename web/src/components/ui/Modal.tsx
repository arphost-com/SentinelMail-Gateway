import { ReactNode, useEffect, useRef } from "react";
import clsx from "clsx";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  // wide doubles the max-width — useful for forms with two columns.
  wide?: boolean;
  xl?: boolean;
}

/**
 * Native <dialog> for accessibility freebies (focus trap, ESC, role=dialog,
 * aria-modal). React rendering keeps the imperative API minimal — useEffect
 * syncs open/closed with showModal()/close().
 */
export function Modal({ open, onClose, title, children, footer, wide, xl }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return;
    const onCancel = (e: Event) => {
      e.preventDefault();
      onClose();
    };
    dlg.addEventListener("cancel", onCancel);
    return () => dlg.removeEventListener("cancel", onCancel);
  }, [onClose]);

  return (
    <dialog
      ref={ref}
      aria-labelledby="modal-title"
      onClick={(e) => {
        // Click on the backdrop (the dialog element itself) closes;
        // clicks inside the inner card don't bubble out.
        if (e.target === ref.current) onClose();
      }}
      className={clsx(
        "max-h-[90vh] rounded border border-border bg-surface text-fg p-0 w-full backdrop:bg-black/40",
        xl ? "max-w-6xl" : wide ? "max-w-3xl" : "max-w-lg"
      )}
    >
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 id="modal-title" className="text-lg font-semibold">{title}</h2>
        <button
          type="button"
          aria-label="Close"
          onClick={onClose}
          className="text-subtle hover:text-fg px-2"
        >
          ×
        </button>
      </div>
      <div className="max-h-[calc(90vh-8rem)] overflow-auto px-4 py-3">{children}</div>
      {footer && <div className="px-4 py-3 border-t border-border flex justify-end gap-2">{footer}</div>}
    </dialog>
  );
}
