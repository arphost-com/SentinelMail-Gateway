import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ListResponse } from "../api/client";
import { Button } from "../components/ui/Button";
import { DataTable, ColumnDef } from "../components/ui/DataTable";
import { Field } from "../components/ui/Field";
import { HelpTooltip } from "../components/ui/HelpTooltip";
import { Input } from "../components/ui/Input";
import { Modal } from "../components/ui/Modal";
import { confirmDanger } from "../components/ui/confirm";

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
    brand_impersonation_enabled?: boolean;
    brand_impersonation_display_name_enabled?: boolean;
    brand_impersonation_subject_enabled?: boolean;
    brand_impersonation_link_mismatch_enabled?: boolean;
    brand_impersonation_third_party_receipts_enabled?: boolean;
    common_scam_detection_enabled?: boolean;
    common_scam_credential_phishing_enabled?: boolean;
    common_scam_payment_support_enabled?: boolean;
    common_scam_tax_document_enabled?: boolean;
    common_scam_malware_lure_enabled?: boolean;
    common_scam_health_miracle_enabled?: boolean;
    common_scam_home_services_enabled?: boolean;
  };
  is_default: boolean;
}

interface Org { id: string; name: string }
interface Domain { id: string; name: string }

interface Form {
  name: string;
  organization_id: string;
  domain_id?: string;
  spam_threshold: number;
  quarantine_threshold: number;
  reject_threshold: number;
  dmarc_enforce: boolean;
  enable_greylist: boolean;
  quarantine_action: string;
  sender_blacklist_enabled: boolean;
  challenge_response_enabled: boolean;
  brand_impersonation_enabled: boolean;
  brand_impersonation_display_name_enabled: boolean;
  brand_impersonation_subject_enabled: boolean;
  brand_impersonation_link_mismatch_enabled: boolean;
  brand_impersonation_third_party_receipts_enabled: boolean;
  common_scam_detection_enabled: boolean;
  common_scam_credential_phishing_enabled: boolean;
  common_scam_payment_support_enabled: boolean;
  common_scam_tax_document_enabled: boolean;
  common_scam_malware_lure_enabled: boolean;
  common_scam_health_miracle_enabled: boolean;
  common_scam_home_services_enabled: boolean;
}

const ACTIONS = ["deliver", "tag", "quarantine", "reject"];
const DETECTION_DEFAULTS = {
  brand_impersonation_enabled: true,
  brand_impersonation_display_name_enabled: true,
  brand_impersonation_subject_enabled: true,
  brand_impersonation_link_mismatch_enabled: true,
  brand_impersonation_third_party_receipts_enabled: true,
  common_scam_detection_enabled: true,
  common_scam_credential_phishing_enabled: true,
  common_scam_payment_support_enabled: true,
  common_scam_tax_document_enabled: true,
  common_scam_malware_lure_enabled: true,
  common_scam_health_miracle_enabled: true,
  common_scam_home_services_enabled: true,
};
const BRAND_OPTIONS: Array<{ key: keyof Form; label: string; help: string }> = [
  { key: "brand_impersonation_display_name_enabled", label: "Display name claims", help: "Hold mail when the sender display name claims a protected brand from an unrelated domain." },
  { key: "brand_impersonation_subject_enabled", label: "Subject/body claims", help: "Use brand names in the subject or body with sensitive account, billing, document, or payment wording." },
  { key: "brand_impersonation_link_mismatch_enabled", label: "Unrelated link domains", help: "Raise confidence when a branded message links to a domain unrelated to the claimed brand or sender." },
  { key: "brand_impersonation_third_party_receipts_enabled", label: "Allow authenticated receipts", help: "Reduce false positives for authenticated PayPal-style receipts that mention a merchant brand." },
];
const SCAM_CATEGORIES: Array<{ key: keyof Form; label: string; help: string }> = [
  { key: "common_scam_credential_phishing_enabled", label: "Credential phishing", help: "Account verification, login, locked-account, and security-alert lures." },
  { key: "common_scam_payment_support_enabled", label: "Payment support scams", help: "Fake charges or transactions that push the user to call support." },
  { key: "common_scam_tax_document_enabled", label: "Tax document phishing", help: "Tax form, refund, or document-ready lures." },
  { key: "common_scam_malware_lure_enabled", label: "Malware lures", help: "Executable, script, macro, or risky attachment wording." },
  { key: "common_scam_health_miracle_enabled", label: "Health miracle spam", help: "Miracle discovery, pain, weight, hearing, vision, or chronic-health spam." },
  { key: "common_scam_home_services_enabled", label: "Home-services lead gen", help: "Septic, roof, windows, HVAC, solar, and similar home-service solicitation spam." },
];
const PRESETS = [
  {
    id: "balanced",
    label: "Balanced",
    hint: "Tag clear spam while avoiding aggressive false positives.",
    values: { spam_threshold: 5, quarantine_threshold: 7, reject_threshold: 15, dmarc_enforce: false, enable_greylist: true, quarantine_action: "tag", sender_blacklist_enabled: true, challenge_response_enabled: false, ...DETECTION_DEFAULTS },
  },
  {
    id: "aggressive",
    label: "Aggressive",
    hint: "Hold more bulk mail and suspicious messages.",
    values: { spam_threshold: 4, quarantine_threshold: 6, reject_threshold: 12, dmarc_enforce: true, enable_greylist: true, quarantine_action: "quarantine", sender_blacklist_enabled: true, challenge_response_enabled: false, ...DETECTION_DEFAULTS },
  },
  {
    id: "permissive",
    label: "Permissive",
    hint: "Tag likely spam but quarantine only high-confidence abuse.",
    values: { spam_threshold: 6, quarantine_threshold: 10, reject_threshold: 18, dmarc_enforce: false, enable_greylist: false, quarantine_action: "tag", sender_blacklist_enabled: true, challenge_response_enabled: false, ...DETECTION_DEFAULTS },
  },
];

export function PoliciesPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);

  const list = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.get<ListResponse<Policy>>("/policies?limit=200"),
  });
  const orgs = useQuery({
    queryKey: ["orgs", "for-select"],
    queryFn: () => api.get<ListResponse<Org>>("/orgs?limit=500"),
  });
  const domains = useQuery({
    queryKey: ["domains", "for-select"],
    queryFn: () => api.get<ListResponse<Domain>>("/domains?limit=500"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/policies/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });

  const orgName = (id?: string) => (id ? orgs.data?.items.find((o) => o.id === id)?.name ?? id.slice(0, 8) : "—");
  const domainName = (id?: string) => (id ? domains.data?.items.find((d) => d.id === id)?.name ?? id.slice(0, 8) : "");

  const columns: ColumnDef<Policy>[] = [
    {
      key: "name",
      header: "Name",
      sortValue: (p) => p.name,
      render: (p) => (
        <span>
          <strong>{p.name}</strong>{" "}
          {p.is_default && <span className="ml-2 rounded bg-muted px-2 py-0.5 text-xs">default</span>}
        </span>
      ),
    },
    { key: "scope", header: "Scope", sortValue: (p) => (p.domain_id ? `domain: ${domainName(p.domain_id)}` : `org: ${orgName(p.organization_id)}`), render: (p) => (p.domain_id ? `domain: ${domainName(p.domain_id)}` : `org: ${orgName(p.organization_id)}`) },
    { key: "spam", header: "Spam ≥", className: "text-right", sortValue: (p) => p.spam_threshold, render: (p) => <span className="tabular-nums">{p.spam_threshold}</span> },
    { key: "quar", header: "Quar ≥", className: "text-right", sortValue: (p) => p.quarantine_threshold, render: (p) => <span className="tabular-nums">{p.quarantine_threshold}</span> },
    { key: "rej", header: "Reject ≥", className: "text-right", sortValue: (p) => p.reject_threshold, render: (p) => <span className="tabular-nums">{p.reject_threshold}</span> },
    { key: "action", header: "Action", sortValue: (p) => p.quarantine_action, render: (p) => p.quarantine_action },
    { key: "challenge", header: "Challenge", sortValue: (p) => p.settings?.challenge_response_enabled ? 1 : 0, render: (p) => (p.settings?.challenge_response_enabled ? "on" : "off") },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Policies</h1>
        <Button onClick={() => setCreating(true)}>+ New policy</Button>
      </div>

      <DataTable
        columns={columns}
        rows={list.data?.items}
        loading={list.isLoading}
        rowKey={(p) => p.id}
        empty="No policies yet — the hardcoded safe default is in effect."
        actions={(p) => (
          <>
            <Button size="sm" variant="secondary" onClick={() => setEditing(p)}>Edit</Button>{" "}
            <Button
              size="sm"
              variant="danger"
              disabled={p.is_default || remove.isPending}
              onClick={() => confirmDanger(`Delete policy "${p.name}"?`) && remove.mutate(p.id)}
            >
              Delete
            </Button>
          </>
        )}
      />

      {creating && (
        <PolicyModal
          title="New policy"
          orgs={orgs.data?.items ?? []}
          domains={domains.data?.items ?? []}
          initial={{
            name: "",
            organization_id: orgs.data?.items?.[0]?.id ?? "",
            domain_id: undefined,
            spam_threshold: 5,
            quarantine_threshold: 10,
            reject_threshold: 15,
            dmarc_enforce: false,
            enable_greylist: true,
            quarantine_action: "tag",
            sender_blacklist_enabled: true,
            challenge_response_enabled: false,
            ...DETECTION_DEFAULTS,
          }}
          onClose={() => setCreating(false)}
          onSubmit={async (v) => {
            await api.post("/policies", toPolicyPayload(v));
            qc.invalidateQueries({ queryKey: ["policies"] });
            setCreating(false);
          }}
        />
      )}

      {editing && (
        <PolicyModal
          title={`Edit ${editing.name}`}
          orgs={orgs.data?.items ?? []}
          domains={domains.data?.items ?? []}
          fixedScope
          initial={{
            name: editing.name,
            organization_id: editing.organization_id ?? "",
            domain_id: editing.domain_id,
            spam_threshold: editing.spam_threshold,
            quarantine_threshold: editing.quarantine_threshold,
            reject_threshold: editing.reject_threshold,
            dmarc_enforce: editing.dmarc_enforce,
            enable_greylist: editing.enable_greylist,
            quarantine_action: editing.quarantine_action,
            sender_blacklist_enabled: editing.settings?.sender_blacklist_enabled ?? true,
            challenge_response_enabled: editing.settings?.challenge_response_enabled ?? false,
            brand_impersonation_enabled: editing.settings?.brand_impersonation_enabled ?? true,
            brand_impersonation_display_name_enabled: editing.settings?.brand_impersonation_display_name_enabled ?? true,
            brand_impersonation_subject_enabled: editing.settings?.brand_impersonation_subject_enabled ?? true,
            brand_impersonation_link_mismatch_enabled: editing.settings?.brand_impersonation_link_mismatch_enabled ?? true,
            brand_impersonation_third_party_receipts_enabled: editing.settings?.brand_impersonation_third_party_receipts_enabled ?? true,
            common_scam_detection_enabled: editing.settings?.common_scam_detection_enabled ?? true,
            common_scam_credential_phishing_enabled: editing.settings?.common_scam_credential_phishing_enabled ?? true,
            common_scam_payment_support_enabled: editing.settings?.common_scam_payment_support_enabled ?? true,
            common_scam_tax_document_enabled: editing.settings?.common_scam_tax_document_enabled ?? true,
            common_scam_malware_lure_enabled: editing.settings?.common_scam_malware_lure_enabled ?? true,
            common_scam_health_miracle_enabled: editing.settings?.common_scam_health_miracle_enabled ?? true,
            common_scam_home_services_enabled: editing.settings?.common_scam_home_services_enabled ?? true,
          }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            await api.patch(`/policies/${editing.id}`, toPolicyPayload(v));
            qc.invalidateQueries({ queryKey: ["policies"] });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

function PolicyModal({
  title,
  orgs,
  domains,
  initial,
  fixedScope,
  onClose,
  onSubmit,
}: {
  title: string;
  orgs: Org[];
  domains: Domain[];
  initial: Form;
  fixedScope?: boolean;
  onClose: () => void;
  onSubmit: (v: Form) => Promise<void>;
}) {
  const [form, setForm] = useState(initial);
  const [preset, setPreset] = useState("custom");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [brandOpen, setBrandOpen] = useState(false);
  const [scamOpen, setScamOpen] = useState(false);

  function setNum(key: keyof Form, raw: string) {
    const n = Number(raw);
    if (Number.isFinite(n)) {
      setPreset("custom");
      setForm({ ...form, [key]: n } as Form);
    }
  }

  function setBool(key: keyof Form, checked: boolean) {
    setPreset("custom");
    setForm({ ...form, [key]: checked } as Form);
  }

  function applyPreset(id: string) {
    setPreset(id);
    if (id === "custom") return;
    const next = PRESETS.find((p) => p.id === id);
    if (!next) return;
    setForm({
      ...form,
      ...next.values,
      name: form.name || `${next.label.toLowerCase()} spam policy`,
    });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (form.quarantine_threshold <= form.spam_threshold) {
      setErr("Quarantine threshold must be greater than spam threshold.");
      return;
    }
    if (form.reject_threshold <= form.quarantine_threshold) {
      setErr("Reject threshold must be greater than quarantine threshold.");
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
        <Field label="Preset" hint="Choose a starting point, then tune individual thresholds if needed.">
          <select
            value={preset}
            onChange={(e) => applyPreset(e.target.value)}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            <option value="custom">Custom</option>
            {PRESETS.map((p) => <option key={p.id} value={p.id}>{p.label} - {p.hint}</option>)}
          </select>
        </Field>
        <Field label="Name" required>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </Field>
        <Field label="Action when over threshold" required>
          <select
            value={form.quarantine_action}
            onChange={(e) => setForm({ ...form, quarantine_action: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </Field>

        <Field label="Scope: organization">
          <select
            disabled={fixedScope}
            value={form.organization_id}
            onChange={(e) => setForm({ ...form, organization_id: e.target.value })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            <option value="">(none)</option>
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        </Field>
        <Field label="Scope: domain (optional)" hint="If set, this policy overrides org policies for this domain.">
          <select
            disabled={fixedScope}
            value={form.domain_id ?? ""}
            onChange={(e) => setForm({ ...form, domain_id: e.target.value || undefined })}
            className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg"
          >
            <option value="">(none)</option>
            {domains.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </Field>

        <Field label="Spam threshold" hint="Score at which message is tagged.">
          <Input type="number" step="0.1" value={form.spam_threshold} onChange={(e) => setNum("spam_threshold", e.target.value)} />
        </Field>
        <Field label="Quarantine threshold" hint="Score at which message is held for review.">
          <Input type="number" step="0.1" value={form.quarantine_threshold} onChange={(e) => setNum("quarantine_threshold", e.target.value)} />
        </Field>
        <Field label="Reject threshold" hint="Score at which message is rejected outright.">
          <Input type="number" step="0.1" value={form.reject_threshold} onChange={(e) => setNum("reject_threshold", e.target.value)} />
        </Field>
        <div className="block text-sm">
          <div className="mb-1 font-medium">Other options</div>
          <div className="flex flex-col gap-1">
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.dmarc_enforce} onChange={(e) => setBool("dmarc_enforce", e.target.checked)} />
                <span>Enforce DMARC reject</span>
              </label>
              <HelpTooltip text="Reject mail that fails a domain's published DMARC reject policy instead of only tagging or quarantining it. Safer for spoofing defense, but stricter for senders with broken authentication." />
            </div>
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.enable_greylist} onChange={(e) => setBool("enable_greylist", e.target.checked)} />
                <span>Enable greylisting</span>
              </label>
              <HelpTooltip text="Temporarily defer unknown senders so legitimate mail servers retry. This blocks some spam runs but can delay first-time mail delivery." />
            </div>
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.sender_blacklist_enabled} onChange={(e) => setBool("sender_blacklist_enabled", e.target.checked)} />
                <span>Use sender blacklist</span>
              </label>
              <HelpTooltip text="When enabled, sender blacklist hits are blocked before downstream delivery and kept for review. Turn this off only for domains that intentionally bypass local sender blocks." />
            </div>
            <div className="inline-flex items-center gap-2 text-sm">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={form.challenge_response_enabled} onChange={(e) => setBool("challenge_response_enabled", e.target.checked)} />
                <span>Challenge-response approval</span>
              </label>
              <HelpTooltip text="Hold first-time inbound senders for this policy until the recipient releases or blocks the sender. Approved senders are allowed for that user; denied senders are blocked for that user." />
            </div>
          </div>
        </div>

        <div className="md:col-span-2 border-t border-border pt-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="inline-flex items-center gap-2 text-sm font-medium">
              <input type="checkbox" checked={form.brand_impersonation_enabled} onChange={(e) => setBool("brand_impersonation_enabled", e.target.checked)} />
              <span>Brand impersonation detection</span>
            </label>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              aria-expanded={brandOpen}
              onClick={() => setBrandOpen((open) => !open)}
            >
              {brandOpen ? "- Hide options" : "+ Show options"}
            </Button>
          </div>
          {brandOpen && (
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              {BRAND_OPTIONS.map((option) => (
                <label key={option.key} className={`flex items-start gap-2 text-sm ${form.brand_impersonation_enabled ? "" : "opacity-60"}`}>
                  <input
                    type="checkbox"
                    checked={Boolean(form[option.key])}
                    disabled={!form.brand_impersonation_enabled}
                    onChange={(e) => setBool(option.key, e.target.checked)}
                  />
                  <span>
                    <span className="block font-medium">{option.label}</span>
                    <span className="block text-xs text-subtle">{option.help}</span>
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>

        <div className="md:col-span-2 border-t border-border pt-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="inline-flex items-center gap-2 text-sm font-medium">
              <input type="checkbox" checked={form.common_scam_detection_enabled} onChange={(e) => setBool("common_scam_detection_enabled", e.target.checked)} />
              <span>Quarantine scam/spam categories</span>
            </label>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              aria-expanded={scamOpen}
              onClick={() => setScamOpen((open) => !open)}
            >
              {scamOpen ? "- Hide categories" : "+ Show categories"}
            </Button>
          </div>
          {scamOpen && (
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              {SCAM_CATEGORIES.map((category) => (
                <label key={category.key} className={`flex items-start gap-2 text-sm ${form.common_scam_detection_enabled ? "" : "opacity-60"}`}>
                  <input
                    type="checkbox"
                    checked={Boolean(form[category.key])}
                    disabled={!form.common_scam_detection_enabled}
                    onChange={(e) => setBool(category.key, e.target.checked)}
                  />
                  <span>
                    <span className="block font-medium">{category.label}</span>
                    <span className="block text-xs text-subtle">{category.help}</span>
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>

        {err && <div role="alert" className="md:col-span-2 text-sm text-danger">{err}</div>}
      </form>
    </Modal>
  );
}

function toPolicyPayload(form: Form) {
  const {
    sender_blacklist_enabled,
    challenge_response_enabled,
    brand_impersonation_enabled,
    brand_impersonation_display_name_enabled,
    brand_impersonation_subject_enabled,
    brand_impersonation_link_mismatch_enabled,
    brand_impersonation_third_party_receipts_enabled,
    common_scam_detection_enabled,
    common_scam_credential_phishing_enabled,
    common_scam_payment_support_enabled,
    common_scam_tax_document_enabled,
    common_scam_malware_lure_enabled,
    common_scam_health_miracle_enabled,
    common_scam_home_services_enabled,
    ...rest
  } = form;
  return {
    ...rest,
    settings: {
      sender_blacklist_enabled,
      challenge_response_enabled,
      brand_impersonation_enabled,
      brand_impersonation_display_name_enabled,
      brand_impersonation_subject_enabled,
      brand_impersonation_link_mismatch_enabled,
      brand_impersonation_third_party_receipts_enabled,
      common_scam_detection_enabled,
      common_scam_credential_phishing_enabled,
      common_scam_payment_support_enabled,
      common_scam_tax_document_enabled,
      common_scam_malware_lure_enabled,
      common_scam_health_miracle_enabled,
      common_scam_home_services_enabled,
    },
  };
}
