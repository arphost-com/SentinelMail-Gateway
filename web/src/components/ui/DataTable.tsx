import { PointerEvent as ReactPointerEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { Button } from "./Button";
import { Card, CardBody } from "./Card";
import { TBody, TD, TH, THead, TR, Table } from "./Table";

type SortDirection = "asc" | "desc";
type SortValue = string | number | boolean | Date | null | undefined;
const DEFAULT_ACTION_COLUMN_PERCENT = 18;

export interface ColumnDef<T> {
  key: string;
  header: ReactNode;
  label?: string;
  className?: string;
  width?: number;
  sortable?: boolean;
  sortValue?: (row: T) => SortValue;
  render: (row: T) => ReactNode;
}

interface ManualPagination {
  total: number;
  offset: number;
  pageSize: number;
  onOffsetChange: (offset: number) => void;
  onPageSizeChange: (pageSize: number) => void;
}

interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  rows: T[] | undefined;
  loading?: boolean;
  empty?: string;
  rowKey: (row: T) => string;
  actions?: (row: T) => ReactNode;
  pagination?: boolean;
  initialPageSize?: number;
  pageSizeOptions?: number[];
  initialSortKey?: string;
  initialSortDirection?: SortDirection;
  manualPagination?: ManualPagination;
  actionColumnWidth?: number;
}

/**
 * Shared resource table with accessible header sorting and pagination.
 */
export function DataTable<T>({
  columns,
  rows,
  loading,
  empty,
  rowKey,
  actions,
  pagination = true,
  initialPageSize = 10,
  pageSizeOptions = [10, 20, 50, 100],
  initialSortKey,
  initialSortDirection = "asc",
  manualPagination,
  actionColumnWidth = DEFAULT_ACTION_COLUMN_PERCENT,
}: DataTableProps<T>) {
  const tableWrapRef = useRef<HTMLDivElement | null>(null);
  const firstSortableKey = columns.find((column) => column.sortable !== false)?.key ?? "";
  const [sortKey, setSortKey] = useState(initialSortKey ?? firstSortableKey);
  const [sortDirection, setSortDirection] = useState<SortDirection>(initialSortDirection);
  const [pageIndex, setPageIndex] = useState(0);
  const [clientPageSize, setClientPageSize] = useState(initialPageSize);
  const [columnPercents, setColumnPercents] = useState<number[]>(() => initialColumnPercents(columns, Boolean(actions), actionColumnWidth));
  const pageSize = manualPagination?.pageSize ?? clientPageSize;
  const activeRows = rows ?? [];
  const actionPercent = actions ? actionColumnWidth : 0;

  useEffect(() => {
    setPageIndex(0);
  }, [activeRows.length, pageSize, sortKey, sortDirection]);

  useEffect(() => {
    setColumnPercents(initialColumnPercents(columns, Boolean(actions), actionColumnWidth));
  }, [columns.map((column) => column.key).join("|"), Boolean(actions), actionColumnWidth]);

  const sortedRows = useMemo(() => {
    const column = columns.find((candidate) => candidate.key === sortKey);
    if (!column || column.sortable === false) return activeRows;
    return [...activeRows].sort((left, right) => {
      const result = compareSortValues(getSortValue(left, column), getSortValue(right, column));
      return sortDirection === "asc" ? result : -result;
    });
  }, [activeRows, columns, sortDirection, sortKey]);

  const localOffset = pageIndex * pageSize;
  const displayRows = manualPagination
    ? sortedRows
    : sortedRows.slice(localOffset, localOffset + pageSize);
  const total = manualPagination?.total ?? sortedRows.length;
  const offset = manualPagination?.offset ?? localOffset;
  const rowCount = displayRows.length;
  const colSpan = columns.length + (actions ? 1 : 0);
  const shouldShowPager = pagination && (loading || total > 0 || Boolean(manualPagination));

  function changeSort(column: ColumnDef<T>) {
    if (column.sortable === false) return;
    if (sortKey === column.key) {
      setSortDirection((current) => current === "asc" ? "desc" : "asc");
      return;
    }
    setSortKey(column.key);
    setSortDirection("asc");
  }

  function changePageSize(nextPageSize: number) {
    if (manualPagination) {
      manualPagination.onPageSizeChange(nextPageSize);
      manualPagination.onOffsetChange(0);
      return;
    }
    setClientPageSize(nextPageSize);
    setPageIndex(0);
  }

  function previousPage() {
    if (manualPagination) {
      manualPagination.onOffsetChange(Math.max(0, manualPagination.offset - pageSize));
      return;
    }
    setPageIndex((current) => Math.max(0, current - 1));
  }

  function nextPage() {
    if (manualPagination) {
      manualPagination.onOffsetChange(manualPagination.offset + pageSize);
      return;
    }
    setPageIndex((current) => current + 1);
  }

  function startColumnResize(index: number, event: ReactPointerEvent<HTMLButtonElement>) {
    const nextIndex = index + 1;
    if (nextIndex >= columnPercents.length) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    const startX = event.clientX;
    const start = [...columnPercents];
    const widthPx = tableWrapRef.current?.getBoundingClientRect().width ?? 1;
    const minPercent = Math.min(14, Math.max(5, 420 / widthPx), ((100 - actionPercent) / columnPercents.length) * 0.75);

    function onMove(moveEvent: PointerEvent) {
      const delta = ((moveEvent.clientX - startX) / widthPx) * 100;
      const current = clamp(start[index] + delta, minPercent, start[index] + start[nextIndex] - minPercent);
      const next = start[index] + start[nextIndex] - current;
      setColumnPercents((existing) => existing.map((value, i) => {
        if (i === index) return current;
        if (i === nextIndex) return next;
        return value;
      }));
    }

    function onUp() {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    }

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp, { once: true });
  }

  const canPrevious = offset > 0;
  const canNext = offset + pageSize < total;
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + rowCount, total);

  return (
    <Card>
      <CardBody className="min-w-0 overflow-hidden p-0">
        <div className="grid gap-3 p-3 md:hidden">
          {loading && <div className="text-center text-subtle py-6">Loading...</div>}
          {!loading && rows && rows.length === 0 && (
            <div className="text-center text-subtle py-6">{empty ?? "No records."}</div>
          )}
          {!loading && displayRows.map((row) => (
            <div key={rowKey(row)} className="rounded border border-border bg-surface p-3 shadow-sm">
              <div className="grid gap-2">
                {columns.map((column) => (
                  <div key={column.key} className="min-w-0">
                    <div className="text-[11px] font-medium uppercase tracking-wide text-subtle">{getHeaderLabel(column)}</div>
                    <div className="min-w-0 break-words text-sm text-fg">{column.render(row)}</div>
                  </div>
                ))}
              </div>
              {actions && (
                <div className="mt-3 flex flex-wrap justify-end gap-2 border-t border-border pt-3">
                  {actions(row)}
                </div>
              )}
            </div>
          ))}
        </div>
        <div ref={tableWrapRef} className="hidden min-w-0 overflow-hidden md:block">
          <Table>
          <colgroup>
            {columns.map((column, index) => (
              <col key={column.key} style={{ width: `${columnPercents[index] ?? 0}%` }} />
            ))}
            {actions && <col style={{ width: `${actionPercent}%` }} />}
          </colgroup>
          <THead>
            <TR>
              {columns.map((c, index) => (
                <TH
                  key={c.key}
                  className={clsx("relative", c.className)}
                  aria-sort={sortKey === c.key ? (sortDirection === "asc" ? "ascending" : "descending") : "none"}
                >
                  {c.sortable === false ? (
                    <span className="block min-w-0 truncate pr-2">{c.header}</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => changeSort(c)}
                      className="inline-flex min-w-0 max-w-full items-center gap-1 rounded pr-2 text-left font-semibold text-fg hover:text-accent focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-muted"
                    >
                      <span className="min-w-0 truncate">{c.header}</span>
                      <span className="text-xs text-subtle" aria-hidden="true">
                        {sortKey === c.key ? (sortDirection === "asc" ? "▲" : "▼") : "↕"}
                      </span>
                    </button>
                  )}
                  {index < columns.length - 1 && (
                    <button
                      type="button"
                      aria-label={`Resize ${getHeaderLabel(c)} column`}
                      title="Resize column"
                      onPointerDown={(event) => startColumnResize(index, event)}
                      className="absolute inset-y-0 right-0 w-2 cursor-col-resize touch-none rounded-none border-r border-transparent hover:border-accent focus:border-accent focus:outline-none"
                    />
                  )}
                </TH>
              ))}
              {actions && <TH className="text-right">Actions</TH>}
            </TR>
          </THead>
          <TBody>
            {loading && (
              <TR>
                <TD colSpan={colSpan} className="text-center text-subtle py-6">Loading…</TD>
              </TR>
            )}
            {!loading && rows && rows.length === 0 && (
              <TR>
                <TD colSpan={colSpan} className="text-center text-subtle py-6">
                  {empty ?? "No records."}
                </TD>
              </TR>
            )}
            {!loading && displayRows.map((row) => (
              <TR key={rowKey(row)}>
                {columns.map((c) => (
                  <TD key={c.key} className={clsx("truncate", c.className)}>{c.render(row)}</TD>
                ))}
                {actions && (
                  <TD className="text-right">
                    <div className="flex flex-wrap justify-end gap-2">{actions(row)}</div>
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
          </Table>
        </div>
      </CardBody>
      {shouldShowPager && (
        <div className="flex flex-col gap-3 border-t border-border px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between">
          <div className="text-subtle">
            {loading ? "Loading…" : `Showing ${start}-${end} of ${total}`}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 text-subtle">
              <span>Rows</span>
              <select
                aria-label="Rows per page"
                value={pageSize}
                onChange={(event) => changePageSize(Number(event.target.value))}
                className="rounded border border-border bg-surface px-2 py-1 text-fg"
              >
                {pageSizeOptions.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </label>
            <Button variant="secondary" size="sm" disabled={loading || !canPrevious} onClick={previousPage}>
              Previous
            </Button>
            <Button variant="secondary" size="sm" disabled={loading || !canNext} onClick={nextPage}>
              Next
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

function getSortValue<T>(row: T, column: ColumnDef<T>): SortValue {
  if (column.sortValue) return column.sortValue(row);
  const direct = (row as Record<string, unknown>)[column.key];
  if (
    typeof direct === "string" ||
    typeof direct === "number" ||
    typeof direct === "boolean" ||
    direct instanceof Date ||
    direct == null
  ) {
    return direct;
  }
  const rendered = column.render(row);
  if (typeof rendered === "string" || typeof rendered === "number") return rendered;
  return "";
}

function getHeaderLabel<T>(column: ColumnDef<T>) {
  if (column.label) return column.label;
  if (typeof column.header === "string") return column.header;
  return column.key;
}

function compareSortValues(left: SortValue, right: SortValue) {
  if (left == null && right == null) return 0;
  if (left == null) return 1;
  if (right == null) return -1;
  const leftValue = left instanceof Date ? left.getTime() : left;
  const rightValue = right instanceof Date ? right.getTime() : right;
  if (typeof leftValue === "number" && typeof rightValue === "number") return leftValue - rightValue;
  if (typeof leftValue === "boolean" && typeof rightValue === "boolean") return Number(leftValue) - Number(rightValue);
  return String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: "base" });
}

function initialColumnPercents<T>(columns: ColumnDef<T>[], hasActions: boolean, actionColumnWidth = DEFAULT_ACTION_COLUMN_PERCENT) {
  if (columns.length === 0) return [];
  const available = hasActions ? 100 - actionColumnWidth : 100;
  const explicitTotal = columns.reduce((sum, column) => sum + Math.max(0, column.width ?? 0), 0);
  if (explicitTotal > 0) {
    return columns.map((column) => ((Math.max(0, column.width ?? 0) || explicitTotal / columns.length) / explicitTotal) * available);
  }
  return columns.map(() => available / columns.length);
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
