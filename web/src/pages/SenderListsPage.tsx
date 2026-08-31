import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ListResponse } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { isAdmin } from "../auth/roles";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { ColumnDef, DataTable } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { HelpTooltip } from "../components/ui/HelpTooltip";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

interface SenderListEntry {
  id: string;
  organization_id?: string;
  domain_id?: string;
  user_id?: string;
  user_email?: string;
  scope: "system" | "org" | "domain" | "user";
  action: "allow" | "block";
  kind: "email" | "domain" | "ip";
  pattern: string;
  sender: string;
  sender_domain: string;
  note?: string;
  blocked_count: number;
  created_at: string;
}

interface Domain {
  id: string;
  organization_id: string;
  name: string;
  is_active: boolean;
}

interface Org {
  id: string;
  name: string;
}

interface User { id: string; organization_id: string; email: string }

interface Policy {
  id: string;
  organization_id?: string;
  domain_id?: string;
  name: string;
  spam_threshold: number;
  quarantine_threshold: number;
  reject_threshold: number;
  dmarc_enforce: boolean;
  enable_greylist: boolean;
  quarantine_action: string;
  settings?: {
    sender_blacklist_enabled?: boolean;
    challenge_response_enabled?: boolean;
    [key: string]: unknown;
  };
}

interface Form {
  action: "allow" | "block";
  kind: "email" | "domain" | "ip";
  scope: "system" | "org" | "domain" | "user";
  organization_id: string;
  domain_id: string;
  user_id: string;
  sender: string;
  note: string;
}

export function SenderListsPage() {
  const qc = useQueryClient();
  const { me } = useAuth();
  const canManage = Boolean(me);
  const canManageAdmin = isAdmin(me?.role);
  const canManageSystem = me?.role === "super_admin";
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("");
  const [entryScope, setEntryScope] = useState("");
  const [userId, setUserId] = useState("");

  const params = new URLSearchParams({ limit: "200" });
  if (search) params.set("q", search);
  if (action) params.set("action", action);
  if (entryScope) params.set("scope", entryScope);
  if (userId) params.set("user_id", userId);

  const entries = useQuery({
    queryKey: ["sender-lists", search, action, entryScope, userId],
    queryFn: () => api.get<ListResponse<SenderListEntry>>(`/sender-lists?${params.toString()}`),
  });
  const domains = useQuery({
    queryKey: ["domains", "for-select"],
    queryFn: () => api.get<ListResponse<Domain>>("/domains?limit=500"),
  });
  const orgs = useQuery({
    queryKey: ["orgs", "for-select"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=500"),
  });
  const users = useQuery({
    queryKey: ["users", "sender-list-select"],
    queryFn: () => api.get<ListResponse<User>>("/users?limit=500"),
    enabled: canManageAdmin,
  });
  const policies = useQuery({
    queryKey: ["policies", "sender-list-settings"],
    queryFn: () => api.get<ListResponse<Policy>>("/policies?limit=500"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/sender-lists/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sender-lists"] }),
  });

  const toggleBlacklist = useMutation({
    mutationFn: async ({ domain, enabled }: { domain: Domain; enabled: boolean }) => {
      const policy = policyForDomain(policies.data?.items ?? [], domain.id);
      if (!policy) {
        await api.post("/policies", {
          organization_id: domain.organization_id,
          domain_id: domain.id,
          name: `${domain.name} spam policy`,
          spam_threshold: 5,
          quarantine_threshold: 7,
          reject_threshold: 15,
          dmarc_enforce: false,
          enable_greylist: true,
          quarantine_action: "tag",
          settings: { sender_blacklist_enabled: enabled, challenge_response_enabled: false },
        });
        return;
      }
      await api.patch(`/policies/${policy.id}`, {
        settings: { ...(policy.settings ?? {}), sender_blacklist_enabled: enabled },
      });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });

  const orgName = (id?: string) => (id ? orgs.data?.items.find((o) => o.id === id)?.name ?? id.slice(0, 8) : "-");
  const domainName = (id?: string) => (id ? domains.data?.items.find((d) => d.id === id)?.name ?? id.slice(0, 8) : "All domains");

  const columns: ColumnDef<SenderListEntry>[] = [
    { key: "action", header: "List", width: 12, sortValue: (e) => e.action, render: (e) => e.action === "allow" ? "Allowlist" : "Blocklist" },
    { key: "sender", header: "Sender / source", width: 24, sortValue: (e) => e.sender, render: (e) => <strong>{e.sender}</strong> },
    { key: "scope", header: "Applies to", width: 26, sortValue: (e) => `${e.scope}:${e.user_email ?? domainName(e.domain_id)}`, render: (e) => scopeLabel(e, orgName, domainName) },
    { key: "blocked", header: "Blocked", width: 10, className: "text-right tabular-nums", sortValue: (e) => e.blocked_count, render: (e) => e.action === "block" ? e.blocked_count.toLocaleString() : "—" },
    { key: "note", header: "Note", width: 24, sortValue: (e) => e.note ?? "", render: (e) => <span className="block truncate" title={e.note}>{e.note || "-"}</span> },
    { key: "created", header: "Created", width: 14, sortValue: (e) => e.created_at, render: (e) => new Date(e.created_at).toLocaleDateString() },
  ];

  return (
    <div className="grid gap-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Allow/block lists</h1>
          <p className="text-sm text-subtle">{canManage ? "Manage trusted and blocked sender addresses and domains for protected mail domains." : "Review trusted and blocked senders visible to your account."}</p>
        </div>
        {canManage && <Button onClick={() => setCreating(true)}>+ Add allow/block rule</Button>}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{canManage ? "Domain blacklist controls" : "Domain blacklist status"}</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {(domains.data?.items ?? []).map((domain) => {
              const policy = policyForDomain(policies.data?.items ?? [], domain.id);
              const enabled = policy?.settings?.sender_blacklist_enabled ?? true;
              return (
                <label key={domain.id} className="flex min-w-0 items-center justify-between gap-3 rounded border border-border bg-surface p-3 text-sm">
                  <span className="min-w-0">
                    <span className="block truncate font-medium" title={domain.name}>{domain.name}</span>
                    <span className="block text-xs text-subtle">{enabled ? "Blacklist active" : "Blacklist ignored"}</span>
                  </span>
                  <span className="inline-flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={enabled}
                      disabled={!canManageAdmin || toggleBlacklist.isPending}
                      onChange={(event) => toggleBlacklist.mutate({ domain, enabled: event.target.checked })}
                      aria-label={`Use blacklist for ${domain.name}`}
                    />
                    <HelpTooltip text="When off, blocklist entries are ignored for this protected domain. Allowlist entries can still release score-based spam decisions." />
                  </span>
                </label>
              );
            })}
            {!domains.isLoading && (domains.data?.items ?? []).length === 0 && (
              <div className="text-sm text-subtle">No protected domains are configured.</div>
            )}
          </div>
        </CardBody>
      </Card>

      <div className="flex flex-wrap items-end gap-3">
        <Field label="Search senders">
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="sender@example.com or example.com" />
        </Field>
        <Field label="List type">
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            <option value="">All</option>
            <option value="allow">Allowlist</option>
            <option value="block">Blocklist</option>
          </select>
        </Field>
        <Field label="Scope">
          <select value={entryScope} onChange={(e) => { setEntryScope(e.target.value); if (e.target.value !== "user") setUserId(""); }} className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg">
            <option value="">All scopes</option><option value="system">System</option><option value="org">Organization</option><option value="domain">Domain</option><option value="user">Mailbox</option>
          </select>
        </Field>
        {canManageAdmin && entryScope === "user" && <Field label="Mailbox">
          <select value={userId} onChange={(e) => setUserId(e.target.value)} className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg">
            <option value="">All mailboxes</option>{(users.data?.items ?? []).map((user) => <option key={user.id} value={user.id}>{user.email}</option>)}
          </select>
        </Field>}
      </div>

      <DataTable
        columns={columns}
        rows={entries.data?.items}
        loading={entries.isLoading}
        rowKey={(entry) => entry.id}
        empty="No allowlist or blocklist senders configured."
        actionColumnWidth={12}
        actions={canManage ? (entry) => (
            <Button
              size="sm"
              variant="danger"
              disabled={remove.isPending}
              onClick={() => confirmDanger(`Undo this ${entry.action} rule for ${entry.sender}? Future mail will return to normal policy evaluation.`) && remove.mutate(entry.id)}
            >
              {entry.action === "allow" ? "Undo allow" : "Undo block"}
            </Button>
          ) : undefined}
      />
      {entries.error && (
        <div role="alert" className="rounded border border-danger bg-danger/10 px-3 py-2 text-sm">
          Allow/block rules failed to load. Retry by refreshing this page.
        </div>
      )}

      {canManage && creating && (
        <SenderListModal
          orgs={orgs.data?.items ?? []}
          domains={domains.data?.items ?? []}
          users={users.data?.items ?? []}
          currentUser={me ? { id: me.user_id, organization_id: me.organization_id, email: me.email } : undefined}
          canManageAdmin={canManageAdmin}
          initial={{
            action: "allow",
            kind: "email",
            scope: canManageAdmin ? (canManageSystem ? "system" : "org") : "user",
            organization_id: me?.organization_id ?? domains.data?.items?.[0]?.organization_id ?? orgs.data?.items?.[0]?.id ?? "",
            domain_id: "",
            user_id: canManageAdmin ? users.data?.items?.[0]?.id ?? "" : me?.user_id ?? "",
            sender: "",
            note: "",
          }}
          onClose={() => setCreating(false)}
          onSubmit={async (form) => {
            await api.post("/sender-lists", {
              action: form.action,
              scope: form.scope,
              organization_id: form.scope === "org" ? form.organization_id : undefined,
              domain_id: form.scope === "domain" ? form.domain_id : undefined,
              user_id: form.scope === "user" ? form.user_id : undefined,
              kind: form.kind,
              sender: form.sender,
              note: form.note,
            });
            qc.invalidateQueries({ queryKey: ["sender-lists"] });
            setCreating(false);
          }}
          canManageSystem={canManageSystem}
        />
      )}
    </div>
  );
}

function SenderListModal({
  orgs,
  domains,
  users,
  currentUser,
  canManageAdmin,
  initial,
  canManageSystem,
  onClose,
  onSubmit,
}: {
  orgs: Org[];
  domains: Domain[];
  users: User[];
  currentUser?: User;
  canManageAdmin: boolean;
  initial: Form;
  canManageSystem: boolean;
  onClose: () => void;
  onSubmit: (form: Form) => Promise<void>;
}) {
  const [form, setForm] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const filteredDomains = useMemo(
    () => domains.filter((domain) => !form.organization_id || domain.organization_id === form.organization_id),
    [domains, form.organization_id],
  );
  const normalizedSenderDomain = normalizeSenderDomain(form.sender);
  const blocksProtectedDomain = form.kind === "domain" && form.action === "block" && domains.some((domain) => domain.name.toLowerCase() === normalizedSenderDomain);

  function updateScope(scope: Form["scope"]) {
    setForm({
      ...form,
      scope,
      domain_id: scope === "domain" ? form.domain_id || filteredDomains[0]?.id || "" : "",
    });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (blocksProtectedDomain) {
      setErr(`Configured protected domain ${normalizedSenderDomain} cannot be blocklisted.`);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await onSubmit(form);
    } catch (error) {
      setErr(error instanceof ApiError ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add allow/block rule"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={submit} disabled={busy || blocksProtectedDomain}>{busy ? "Saving..." : "Save"}</Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid gap-3">
        <Field label="List type" required>
          <select
            value={form.action}
            onChange={(e) => setForm({ ...form, action: e.target.value as Form["action"] })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {form.kind !== "ip" && <option value="allow">Allowlist</option>}
            <option value="block">Blocklist</option>
          </select>
        </Field>
        <Field label="Rule type" required>
          <select
            value={form.kind}
            onChange={(e) => {
              const kind = e.target.value as Form["kind"];
              setForm({ ...form, kind, action: kind === "ip" ? "block" : form.action, sender: "" });
            }}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            <option value="email">Exact email address</option>
            <option value="domain">Verified sender domain</option>
            <option value="ip">Source IP or CIDR (block only)</option>
          </select>
        </Field>
        <Field label={form.kind === "email" ? "Sender email" : form.kind === "ip" ? "Source IP or CIDR" : "Sender domain"} hint={form.kind === "domain" ? "domain.com applies to that domain and its subdomains." : undefined}>
          <Input
            value={form.sender}
            onChange={(e) => setForm({ ...form, sender: e.target.value.trim().toLowerCase() })}
            placeholder={form.kind === "email" ? "sender@example.com" : form.kind === "ip" ? "192.0.2.44 or 192.0.2.0/24" : "example.com"}
            required
          />
        </Field>
        {blocksProtectedDomain && (
          <div role="alert" className="text-sm text-danger">
            Configured protected domain {normalizedSenderDomain} cannot be blocklisted.
          </div>
        )}
        <Field label="Applies to" required>
          <select
            value={form.scope}
            onChange={(e) => updateScope(e.target.value as Form["scope"])}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
            required
          >
            {canManageSystem && <option value="system">System-wide</option>}
            {canManageAdmin && <option value="domain">One protected domain</option>}
            {canManageAdmin && <option value="org">Whole organization</option>}
            <option value="user">One mailbox</option>
          </select>
        </Field>
        {canManageAdmin && form.scope !== "system" && form.scope !== "user" && (
          <Field label="Organization" required>
            <select
              value={form.organization_id}
              onChange={(e) => {
                const nextOrg = e.target.value;
                const nextDomain = domains.find((domain) => domain.organization_id === nextOrg)?.id ?? "";
                setForm({ ...form, organization_id: nextOrg, domain_id: form.scope === "domain" ? nextDomain : "" });
              }}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              required
            >
              {orgs.map((org) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </select>
          </Field>
        )}
        {form.scope === "domain" && (
          <Field label="Protected domain" required>
            <select
              value={form.domain_id}
              onChange={(e) => setForm({ ...form, domain_id: e.target.value })}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              required
            >
              {filteredDomains.map((domain) => <option key={domain.id} value={domain.id}>{domain.name}</option>)}
            </select>
          </Field>
        )}
        {form.scope === "user" && (
          <Field label="Mailbox" required>
            <select
              value={form.user_id}
              onChange={(e) => setForm({ ...form, user_id: e.target.value })}
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
              required
            >
              {(canManageAdmin ? users : currentUser ? [currentUser] : []).map((user) => <option key={user.id} value={user.id}>{user.email}</option>)}
            </select>
          </Field>
        )}
        <Field label="Note">
          <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="Reason or ticket reference" />
        </Field>
        {err && <div role="alert" className="text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}

function policyForDomain(policies: Policy[], domainID: string) {
  return policies.find((policy) => policy.domain_id === domainID);
}

function normalizeSenderDomain(value: string) {
  let domain = value.trim().toLowerCase();
  if (domain.startsWith("*@")) domain = domain.slice(2);
  if (domain.startsWith("@")) domain = domain.slice(1);
  if (domain.includes("@")) domain = domain.slice(domain.lastIndexOf("@") + 1);
  return domain.replace(/\.$/, "");
}

function scopeLabel(entry: SenderListEntry, orgName: (id?: string) => string, domainName: (id?: string) => string) {
  if (entry.scope === "system") return "System-wide";
  if (entry.scope === "domain") return domainName(entry.domain_id);
  if (entry.scope === "user") return entry.user_email ? `Mailbox: ${entry.user_email}` : "Mailbox-specific";
  return `${orgName(entry.organization_id)} org`;
}
