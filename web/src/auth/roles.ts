// Roles ordered low → high. Source of truth for the frontend; the backend
// enforces the same hierarchy independently (internal/users.canAssignRole +
// internal/tenant.Scope.CanAdmin).
export const ROLES = ["org_user", "org_admin", "msp_admin", "super_admin"] as const;
export type Role = (typeof ROLES)[number];

const TIER: Record<Role, number> = {
  org_user: 1,
  org_admin: 2,
  msp_admin: 3,
  super_admin: 4,
};

export function roleAtLeast(actual: string | undefined, required: Role): boolean {
  if (!actual) return false;
  return (TIER[actual as Role] ?? 0) >= TIER[required];
}

export function isAdmin(role: string | undefined): boolean {
  return roleAtLeast(role, "org_admin");
}
