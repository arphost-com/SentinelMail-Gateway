import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminStats, adminWindowLabel } from "../api/adminStats";
import { ApiError, api, ListResponse } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { Button } from "../components/ui/Button";
import { DataTable, ColumnDef } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface User {
  id: string;
  organization_id: string;
  email: string;
  role: string;
  display_name?: string;
  is_active: boolean;
  mfa_enrolled: boolean;
  last_login_at?: string;
}
interface Org { id: string; name: string }
interface Form {
  organization_id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
  password: string;
}

const ROLES = ["super_admin", "msp_admin", "org_admin", "org_user"];

export function UsersPage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<User | null>(null);
  const [creating, setCreating] = useState(false);
  const [pwUser, setPwUser] = useState<User | null>(null);
  const [statsUser, setStatsUser] = useState<User | null>(null);
  const [manageUser, setManageUser] = useState<User | null>(null);
  const [statsWindow, setStatsWindow] = useState("7d");

  const list = useQuery({
    queryKey: ["users"],
    queryFn: () => api.get<ListResponse<User>>("/users?limit=200"),
  });
  const orgs = useQuery({
    queryKey: ["orgs", "for-select"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=500"),
  });
  const stats = useQuery({
    queryKey: ["admin-stats", statsWindow],
    queryFn: () => api.get<AdminStats>(`/reports/admin-stats?window=${statsWindow}`),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const disableMFA = useMutation({
    mutationFn: (id: string) => api.post(`/users/${id}/mfa/disable`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const impersonate = useMutation({
    mutationFn: (id: string) => api.post(`/auth/impersonate/start`, { target_user_id: id }),
    onSuccess: () => {
      // Drop client-side caches; a hard reload is the simplest way to
      // re-fetch /me and rebuild role-scoped nav for the target user.
      window.location.assign("/");
    },
  });

  const orgName = (id: string) => orgs.data?.items.find((o) => o.id === id)?.name ?? id.slice(0, 8);
  const userStats = (id: string) => stats.data?.users.find((row) => row.id === id);

  const columns: ColumnDef<User>[] = [
    {
      key: "email",
      header: "Email",
      width: 45,
      className: "whitespace-nowrap",
      render: (u) => <span title={u.email} className="block truncate">{u.email}</span>,
    },
    {
      key: "last",
      header: "Last sign-in",
      width: 24,
      className: "whitespace-nowrap",
      sortValue: (u) => u.last_login_at ?? "",
      render: (u) => (
        <span title={u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}>
          {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
        </span>
      ),
    },
    {
      key: "active",
      header: "Active",
      width: 13,
      className: "whitespace-nowrap",
      sortValue: (u) => u.is_active,
      render: (u) => (u.is_active ? "Yes" : "No"),
    },
  ];

  return (
    <div>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold">Users</h1>
          <p className="text-sm text-subtle">User message statistics cover {adminWindowLabel(statsWindow)}.</p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="block text-subtle mb-1">Stats window</span>
            <select
              value={statsWindow}
              onChange={(event) => setStatsWindow(event.target.value)}
              className="block rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
            </select>
          </label>
          <Button onClick={() => setCreating(true)}>+ New user</Button>
        </div>
      </div>

      {stats.error && (
        <div role="alert" className="text-sm text-danger mb-3">
          {stats.error instanceof Error ? stats.error.message : "Failed to load user statistics"}
        </div>
      )}

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        rowKey={(u) => u.id}
        empty="No users yet."
        actionColumnWidth={24}
        actions={(u) => (
          <>
            <Button size="sm" variant="secondary" onClick={() => setStatsUser(u)}>View user</Button>
            <Button size="sm" variant="secondary" onClick={() => setManageUser(u)}>Manage</Button>
          </>
        )}
      />

      {creating && (
        <UserModal
          title="New user"
          orgs={orgs.data?.items ?? []}
          mode="create"
          initial={{
            organization_id: orgs.data?.items?.[0]?.id ?? "",
            email: "",
            display_name: "",
            role: "org_user",
            is_active: true,
            password: "",
          }}
          onClose={() => setCreating(false)}
          onSubmit={async (v) => {
            await api.post("/users", v);
            qc.invalidateQueries({ queryKey: ["users"] });
            setCreating(false);
          }}
        />
      )}

      {editing && (
        <UserModal
          title={`Edit ${editing.email}`}
          orgs={orgs.data?.items ?? []}
          mode="edit"
          initial={{
            organization_id: editing.organization_id,
            email: editing.email,
            display_name: editing.display_name ?? "",
            role: editing.role,
            is_active: editing.is_active,
            password: "",
          }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            const { password, organization_id, ...patch } = v;
            void password;
            void organization_id;
            await api.patch(`/users/${editing.id}`, patch);
            qc.invalidateQueries({ queryKey: ["users"] });
            setEditing(null);
          }}
        />
      )}

      {pwUser && (
        <PasswordModal
          email={pwUser.email}
          onClose={() => setPwUser(null)}
          onSubmit={async (pw) => {
            await api.post(`/users/${pwUser.id}/password`, { password: pw });
            setPwUser(null);
          }}
        />
      )}

      {statsUser && (
        <UserDetailsModal
          user={statsUser}
          organization={orgName(statsUser.organization_id)}
          statsWindow={adminWindowLabel(statsWindow)}
          stats={userStats(statsUser.id)}
          onClose={() => setStatsUser(null)}
        />
      )}

      {manageUser && (
        <UserManageModal
          user={manageUser}
          canDisableMFA={manageUser.mfa_enrolled && manageUser.id !== me?.user_id}
          canImpersonate={me?.role === "super_admin" && manageUser.id !== me?.user_id}
          canDelete={manageUser.id !== me?.user_id}
          busy={remove.isPending || disableMFA.isPending || impersonate.isPending}
          onClose={() => setManageUser(null)}
          onEdit={() => {
            setEditing(manageUser);
            setManageUser(null);
          }}
          onResetPassword={() => {
            setPwUser(manageUser);
            setManageUser(null);
          }}
          onDisableMFA={() => {
            if (confirmDanger(`Disable 2FA for ${manageUser.email}? They'll be signed out and have to re-enroll on next login.`)) {
              disableMFA.mutate(manageUser.id);
              setManageUser(null);
            }
          }}
          onImpersonate={() => {
            if (confirmDanger(`Sign in as ${manageUser.email}? Your current session will be replaced; use the banner at the top to switch back.`)) {
              impersonate.mutate(manageUser.id);
            }
          }}
          onDelete={() => {
            if (confirmDanger(`Delete user ${manageUser.email}?`)) {
              remove.mutate(manageUser.id);
              setManageUser(null);
            }
          }}
        />
      )}
    </div>
  );
}

function UserDetailsModal({
  user,
  organization,
  statsWindow,
  stats,
  onClose,
}: {
  user: User;
  organization: string;
  statsWindow: string;
  stats: AdminStats["users"][number] | undefined;
  onClose: () => void;
}) {
  const fields = [
    ["Email", user.email],
    ["Name", user.display_name || "None"],
    ["Organization", organization],
    ["Role", user.role],
    ["Active", user.is_active ? "Yes" : "No"],
    ["MFA", user.mfa_enrolled ? "Enrolled" : "Not enrolled"],
    ["Last sign-in", user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "Never"],
    ["Processed", stats?.processed.toLocaleString() ?? "0"],
    ["Quarantined", stats?.quarantined.toLocaleString() ?? "0"],
    ["Reported", stats?.reported_threats.toLocaleString() ?? "0"],
  ];

  return (
    <Modal
      open
      onClose={onClose}
      title={`User: ${user.email}`}
      footer={<Button variant="secondary" onClick={onClose}>Close</Button>}
    >
      <div className="grid gap-3">
        <p className="text-sm text-subtle">Settings and statistics for {statsWindow}.</p>
        <dl className="grid gap-2 sm:grid-cols-2">
          {fields.map(([label, value]) => (
            <div key={label} className="min-w-0 rounded border border-border bg-muted px-3 py-2">
              <dt className="text-xs font-medium uppercase text-subtle">{label}</dt>
              <dd className="truncate text-sm text-fg" title={value}>{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </Modal>
  );
}

function UserManageModal({
  user,
  canDisableMFA,
  canImpersonate,
  canDelete,
  busy,
  onClose,
  onEdit,
  onResetPassword,
  onDisableMFA,
  onImpersonate,
  onDelete,
}: {
  user: User;
  canDisableMFA: boolean;
  canImpersonate: boolean;
  canDelete: boolean;
  busy: boolean;
  onClose: () => void;
  onEdit: () => void;
  onResetPassword: () => void;
  onDisableMFA: () => void;
  onImpersonate: () => void;
  onDelete: () => void;
}) {
  return (
    <Modal
      open
      onClose={onClose}
      title={`Manage ${user.email}`}
      footer={<Button variant="secondary" onClick={onClose}>Close</Button>}
    >
      <div className="grid gap-3">
        <div className="grid gap-2 sm:grid-cols-2">
          <Button variant="secondary" onClick={onEdit}>Edit settings</Button>
          <Button variant="secondary" onClick={onResetPassword}>Reset password</Button>
          {canDisableMFA && (
            <Button variant="secondary" disabled={busy} onClick={onDisableMFA}>Disable 2FA</Button>
          )}
          {canImpersonate && (
            <Button variant="secondary" disabled={busy} onClick={onImpersonate}>Impersonate</Button>
          )}
        </div>
        <div className="border-t border-border pt-3">
          <Button variant="danger" disabled={!canDelete || busy} onClick={onDelete}>Delete user</Button>
        </div>
      </div>
    </Modal>
  );
}

function UserModal({
  title,
  orgs,
  initial,
  mode,
  onClose,
  onSubmit,
}: {
  title: string;
  orgs: Org[];
  initial: Form;
  mode: "create" | "edit";
  onClose: () => void;
  onSubmit: (v: Form) => Promise<void>;
}) {
  const [form, setForm] = useState(initial);
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (mode === "create" && form.password !== confirmPw) {
      setErr("Passwords do not match.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(form);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      wide
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid gap-3 grid-cols-1 md:grid-cols-2">
        <Field label="Email" required>
          <Input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </Field>
        <Field label="Display name">
          <Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
        </Field>
        <Field label="Organization" required>
          <select
            disabled={mode === "edit"}
            value={form.organization_id}
            onChange={(e) => setForm({ ...form, organization_id: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        </Field>
        <Field label="Role" required>
          <select
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </Field>
        {mode === "create" && (
          <>
            <Field label="Initial password" required hint="At least 12 characters.">
              <Input
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
              />
            </Field>
            <Field label="Confirm password" required>
              <Input
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
              />
            </Field>
          </>
        )}
        <Field label="Active">
          <label className="inline-flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
            />
            User can sign in
          </label>
        </Field>
        {err && <div role="alert" className="md:col-span-2 text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}

function PasswordModal({
  email,
  onClose,
  onSubmit,
}: {
  email: string;
  onClose: () => void;
  onSubmit: (pw: string) => Promise<void>;
}) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pw !== confirm) {
      setErr("Passwords do not match.");
      return;
    }
    if (pw.length < 12) {
      setErr("Password must be at least 12 characters.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(pw);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Reset password for ${email}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy}>{busy ? "Saving…" : "Reset"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="New password" required>
          <Input type="password" required minLength={12} value={pw} onChange={(e) => setPw(e.target.value)} />
        </Field>
        <Field label="Confirm password" required>
          <Input type="password" required minLength={12} value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <p className="text-xs text-subtle">
          Resetting the password revokes all of the user's other sessions.
        </p>
        {err && <div role="alert" className="text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}
