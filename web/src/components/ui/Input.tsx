import { InputHTMLAttributes, forwardRef } from "react";
import clsx from "clsx";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, ...rest },
  ref
) {
  return (
    <input
      ref={ref}
      {...rest}
      className={clsx(
        "block w-full rounded border border-border bg-surface px-3 py-2 text-fg placeholder:text-subtle focus:border-accent",
        className
      )}
    />
  );
});
