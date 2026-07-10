/**
 * Tiny confirm wrapper. Using window.confirm is OK for destructive admin
 * actions in MVP — replace with a styled modal later if product wants it.
 * Centralised so we can swap implementations without hunting through pages.
 */
export function confirmDanger(message: string): boolean {
  if (typeof window === "undefined") return false;
  // eslint-disable-next-line no-alert
  return window.confirm(message);
}
