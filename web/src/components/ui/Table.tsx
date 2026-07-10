import { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";
import clsx from "clsx";

export function Table({ className, ...rest }: HTMLAttributes<HTMLTableElement>) {
  return <table {...rest} className={clsx("w-full table-fixed text-left text-sm", className)} />;
}

export function THead(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead {...props} />;
}

export function TBody(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody {...props} />;
}

export function TR({ className, ...rest }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr {...rest} className={clsx("border-b border-border last:border-0", className)} />;
}

export function TH({ className, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      {...rest}
      className={clsx("min-w-0 overflow-hidden px-3 py-2 font-semibold text-subtle bg-muted", className)}
    />
  );
}

export function TD({ className, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td {...rest} className={clsx("min-w-0 overflow-hidden px-3 py-2 align-top", className)} />;
}
