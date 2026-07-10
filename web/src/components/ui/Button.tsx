import { ButtonHTMLAttributes, forwardRef } from "react";
import clsx from "clsx";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const variantClasses: Record<Variant, string> = {
  primary: "bg-accent text-accentFg hover:opacity-90 disabled:opacity-50",
  secondary: "bg-muted text-fg hover:bg-border disabled:opacity-50",
  ghost: "bg-transparent text-fg hover:bg-muted",
  danger: "bg-danger text-white hover:opacity-90 disabled:opacity-50",
};

const sizeClasses: Record<Size, string> = {
  sm: "px-2.5 py-1 text-sm",
  md: "px-3.5 py-2",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", size = "md", className, ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      {...rest}
      className={clsx(
        "inline-flex min-w-0 max-w-full items-center justify-center whitespace-nowrap rounded border border-transparent text-center font-medium transition-colors",
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
    />
  );
});
