import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../../api/client";
import { useAuth } from "../../auth/AuthProvider";
import { Button } from "../../components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "../../components/ui/Card";
import { Field } from "../../components/ui/Field";
import { HelpTooltip } from "../../components/ui/HelpTooltip";
import { Input } from "../../components/ui/Input";

interface UserSelf {
  id: string;
  email: string;
  role: string;
  mfa_enrolled: boolean;
  phishing_alert_frequency: "off" | "immediate" | "daily" | "weekly";
  bulk_completion_notification: "email" | "in_app" | "both" | "off";
}

interface MFASetupResp {
  otpauth_url: string;
  secret_base32: string;
  qr_png_base64: string;
}

export function AccountTab() {
  const { me } = useAuth();

  // Read just our own row. /users/{id} allows the caller to read users
  // within their tenant scope, including themselves, so org_user can hit
  // this without needing the listing permission.
  const self = useQuery({
    queryKey: ["self", me?.user_id],
    queryFn: () => api.get<UserSelf>(`/users/${me!.user_id}`),
    enabled: !!me?.user_id,
    refetchOnWindowFocus: true,
  });

  // org_user can update personal notification preferences, but email changes
  // still require an admin.
  const canEditEmail = me?.role === "super_admin" || me?.role === "msp_admin" || me?.role === "org_admin";

  return (
    <div className="flex flex-col gap-4">
      <EmailCard userId={me?.user_id} currentEmail={self.data?.email ?? ""} editable={canEditEmail} refetch={() => self.refetch()} />
      <PhishingAlertsCard
        userId={me?.user_id}
        frequency={self.data?.phishing_alert_frequency ?? "weekly"}
        refetch={() => self.refetch()}
      />
      <BackgroundCompletionCard
        userId={me?.user_id}
        preference={self.data?.bulk_completion_notification ?? "email"}
        refetch={() => self.refetch()}
      />
      <PasswordCard userId={me?.user_id} />
      <MFACard enrolled={self.data?.mfa_enrolled ?? false} loading={self.isLoading} refetch={() => self.refetch()} />
    </div>
  );
}

// ------------------- email change -------------------

function EmailCard({
  userId,
  currentEmail,
  editable,
  refetch,
}: {
  userId: string | undefined;
  currentEmail: string;
  editable: boolean;
  refetch: () => void;
}) {
  const [email, setEmail] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);
  const qc = useQueryClient();

  const change = useMutation({
    mutationFn: (newEmail: string) => api.patch(`/users/${userId}`, { email: newEmail }),
    onSuccess: () => {
      setOk(true);
      setEmail("");
      setErr(null);
      qc.invalidateQueries({ queryKey: ["self"] });
      refetch();
    },
    onError: (e) => {
      setOk(false);
      setErr(e instanceof ApiError ? e.message : String(e));
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setOk(false);
    if (!userId) return;
    const next = email.trim().toLowerCase();
    if (!next || !next.includes("@")) {
      setErr("Enter a valid email address.");
      return;
    }
    if (next === currentEmail.toLowerCase()) {
      setErr("That's already your current email.");
      return;
    }
    change.mutate(next);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Email address</CardTitle>
      </CardHeader>
      <CardBody>
        <p className="text-sm text-subtle mb-3">
          Current: <code className="font-mono">{currentEmail || "…"}</code>
        </p>
        {!editable && (
          <p className="text-sm text-subtle">
            Ask an administrator to change your email address.
          </p>
        )}
        {editable && (
          <form onSubmit={submit} className="flex flex-col gap-3 max-w-sm">
          <Field label="New email" required help="Your email address is also used to scope your per-user mailbox view. Changing it affects which received-message copies you can see.">
              <Input
                type="email"
                autoComplete="email"
                required
                value={email}
                placeholder="you@example.com"
                onChange={(e) => setEmail(e.target.value)}
              />
            </Field>
            {err && <div role="alert" className="text-sm text-danger">{err}</div>}
            {ok && <div role="status" className="text-sm text-success">Email updated. Use the new address next time you sign in.</div>}
            <div>
              <Button type="submit" disabled={change.isPending || !email.trim()}>
                {change.isPending ? "Saving…" : "Change email"}
              </Button>
            </div>
          </form>
        )}
      </CardBody>
    </Card>
  );
}

// ------------------- phishing alerts -------------------

function PhishingAlertsCard({
  userId,
  frequency,
  refetch,
}: {
  userId: string | undefined;
  frequency: UserSelf["phishing_alert_frequency"];
  refetch: () => void;
}) {
  const [value, setValue] = useState<UserSelf["phishing_alert_frequency"]>(frequency);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);
  const qc = useQueryClient();

  useEffect(() => {
    setValue(frequency);
  }, [frequency]);

  const change = useMutation({
    mutationFn: (next: UserSelf["phishing_alert_frequency"]) =>
      api.patch(`/users/${userId}`, { phishing_alert_frequency: next }),
    onSuccess: () => {
      setOk(true);
      setErr(null);
      qc.invalidateQueries({ queryKey: ["self"] });
      refetch();
    },
    onError: (e) => {
      setOk(false);
      setErr(e instanceof ApiError ? e.message : String(e));
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setOk(false);
    if (!userId) return;
    change.mutate(value);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Phishing alerts</CardTitle>
      </CardHeader>
      <CardBody>
        <form onSubmit={submit} className="flex flex-col gap-3 max-w-sm">
          <Field label="Email alert frequency" help="Controls how often SentinelMail emails you when phishing is quarantined for your mailbox. Weekly is the default.">
            <select
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg focus:border-accent"
              value={value}
              onChange={(e) => {
                setOk(false);
                setErr(null);
                setValue(e.target.value as UserSelf["phishing_alert_frequency"]);
              }}
            >
              <option value="weekly">Weekly</option>
              <option value="daily">Daily</option>
              <option value="immediate">Every phishing email</option>
              <option value="off">Off</option>
            </select>
          </Field>
          {err && <div role="alert" className="text-sm text-danger">{err}</div>}
          {ok && <div role="status" className="text-sm text-success">Phishing alert preference updated.</div>}
          <div>
            <Button type="submit" disabled={change.isPending || value === frequency}>
              {change.isPending ? "Saving…" : "Save alerts"}
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

// ------------------- background completions -------------------

function BackgroundCompletionCard({
  userId,
  preference,
  refetch,
}: {
  userId: string | undefined;
  preference: UserSelf["bulk_completion_notification"];
  refetch: () => void;
}) {
  const [value, setValue] = useState<UserSelf["bulk_completion_notification"]>(preference);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);
  const qc = useQueryClient();

  useEffect(() => {
    setValue(preference);
  }, [preference]);

  const change = useMutation({
    mutationFn: (next: UserSelf["bulk_completion_notification"]) =>
      api.patch(`/users/${userId}`, { bulk_completion_notification: next }),
    onSuccess: () => {
      setOk(true);
      setErr(null);
      qc.invalidateQueries({ queryKey: ["self"] });
      refetch();
    },
    onError: (e) => {
      setOk(false);
      setErr(e instanceof ApiError ? e.message : String(e));
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setOk(false);
    if (!userId) return;
    change.mutate(value);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Background task completions</CardTitle>
      </CardHeader>
      <CardBody>
        <form onSubmit={submit} className="flex flex-col gap-3 max-w-sm">
          <Field label="Completion notifications" help="Controls completion notices for background bulk quarantine actions. In-app status is shown in the current app session; email sends a message after the task finishes.">
            <select
              className="block w-full rounded border border-border bg-surface px-3 py-2 text-fg focus:border-accent"
              value={value}
              onChange={(e) => {
                setOk(false);
                setErr(null);
                setValue(e.target.value as UserSelf["bulk_completion_notification"]);
              }}
            >
              <option value="email">Email</option>
              <option value="in_app">In-app only</option>
              <option value="both">In-app and email</option>
              <option value="off">Off</option>
            </select>
          </Field>
          {err && <div role="alert" className="text-sm text-danger">{err}</div>}
          {ok && <div role="status" className="text-sm text-success">Background completion preference updated.</div>}
          <div>
            <Button type="submit" disabled={change.isPending || value === preference}>
              {change.isPending ? "Saving…" : "Save completion notices"}
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

// ------------------- password change -------------------

function PasswordCard({ userId }: { userId: string | undefined }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const change = useMutation({
    mutationFn: (newPw: string) => api.post(`/users/${userId}/password`, { password: newPw }),
    onSuccess: () => {
      setOk(true);
      setPw("");
      setConfirm("");
      setErr(null);
    },
    onError: (e) => {
      setOk(false);
      setErr(e instanceof ApiError ? e.message : String(e));
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setOk(false);
    if (!userId) return;
    if (pw !== confirm) {
      setErr("Passwords do not match.");
      return;
    }
    if (pw.length < 12) {
      setErr("Password must be at least 12 characters.");
      return;
    }
    change.mutate(pw);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
      </CardHeader>
      <CardBody>
        <p className="text-sm text-subtle mb-3">
          A successful change revokes all your other active sessions on this account.
        </p>
        <form onSubmit={submit} className="flex flex-col gap-3 max-w-sm">
          <Field label="New password" hint="At least 12 characters" required help="Changing your password revokes other active sessions for this account. Use a unique password.">
            <Input
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
              value={pw}
              onChange={(e) => setPw(e.target.value)}
            />
          </Field>
          <Field label="Confirm new password" required>
            <Input
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Field>
          {err && <div role="alert" className="text-sm text-danger">{err}</div>}
          {ok && <div role="status" className="text-sm text-success">Password updated.</div>}
          <div>
            <Button type="submit" disabled={change.isPending || pw.length < 12 || pw !== confirm}>
              {change.isPending ? "Saving…" : "Change password"}
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

// ------------------- MFA -------------------

function MFACard({
  enrolled,
  loading,
  refetch,
}: {
  enrolled: boolean;
  loading: boolean;
  refetch: () => void;
}) {
  const qc = useQueryClient();
  const [setup, setSetup] = useState<MFASetupResp | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [confirmErr, setConfirmErr] = useState<string | null>(null);
  const [disableCode, setDisableCode] = useState("");
  const [disableErr, setDisableErr] = useState<string | null>(null);

  const startSetup = useMutation({
    mutationFn: () => api.post<MFASetupResp>("/auth/mfa/setup"),
    onSuccess: (r) => {
      setSetup(r);
      setConfirmCode("");
      setConfirmErr(null);
    },
  });

  const confirm = useMutation({
    mutationFn: (code: string) => api.post("/auth/mfa/confirm", { code }),
    onSuccess: () => {
      setSetup(null);
      setConfirmCode("");
      qc.invalidateQueries({ queryKey: ["self"] });
      refetch();
    },
    onError: (e) => setConfirmErr(e instanceof ApiError ? e.message : String(e)),
  });

  const disable = useMutation({
    mutationFn: (code: string) => api.post("/auth/mfa/disable", { code }),
    onSuccess: () => {
      setDisableCode("");
      qc.invalidateQueries({ queryKey: ["self"] });
      refetch();
    },
    onError: (e) => setDisableErr(e instanceof ApiError ? e.message : String(e)),
  });

  function submitConfirm(e: FormEvent) {
    e.preventDefault();
    confirm.mutate(confirmCode.trim());
  }
  function submitDisable(e: FormEvent) {
    e.preventDefault();
    disable.mutate(disableCode.trim());
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="inline-flex items-center gap-2">
          <span>Two-factor authentication</span>
          <HelpTooltip text="Two-factor authentication requires a current authenticator code after password login and protects the account if the password is stolen." />
        </CardTitle>
      </CardHeader>
      <CardBody>
        <p className="text-sm mb-3">
          Status:{" "}
          {loading ? (
            <span className="text-subtle">…</span>
          ) : enrolled ? (
            <span className="text-success font-semibold">Enabled</span>
          ) : (
            <span className="text-subtle">Disabled</span>
          )}
        </p>

        {!enrolled && !setup && (
          <Button onClick={() => startSetup.mutate()} disabled={startSetup.isPending}>
            {startSetup.isPending ? "Preparing…" : "Enable two-factor"}
          </Button>
        )}

        {setup && !enrolled && (
          <div className="mt-3">
            <p className="text-sm mb-2">
              Scan the QR code with your authenticator app, then enter the 6-digit code to confirm:
            </p>
            <div className="flex items-start gap-4">
              <img
                src={`data:image/png;base64,${setup.qr_png_base64}`}
                alt="MFA QR code"
                width={220}
                height={220}
                className="border border-border rounded bg-white p-2"
              />
              <div className="text-sm">
                <div className="mb-2">Or enter this key manually:</div>
                <code className="block text-xs bg-muted p-2 rounded break-all max-w-xs">
                  {setup.secret_base32}
                </code>
                <details className="mt-2 text-xs text-subtle">
                  <summary className="cursor-pointer">otpauth URL</summary>
                  <code className="block mt-1 break-all">{setup.otpauth_url}</code>
                </details>
              </div>
            </div>
            <form onSubmit={submitConfirm} className="mt-4 flex flex-col gap-2 max-w-xs">
              <Field label="6-digit code" required help="Enter the current time-based code from your authenticator app to finish enrollment.">
                <Input
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  value={confirmCode}
                  onChange={(e) => setConfirmCode(e.target.value)}
                  autoFocus
                />
              </Field>
              {confirmErr && <div role="alert" className="text-sm text-danger">{confirmErr}</div>}
              <div className="flex gap-2">
                <Button type="submit" disabled={confirm.isPending || confirmCode.length !== 6}>
                  {confirm.isPending ? "Confirming…" : "Confirm"}
                </Button>
                <Button type="button" variant="secondary" onClick={() => setSetup(null)}>
                  Cancel
                </Button>
              </div>
            </form>
          </div>
        )}

        {enrolled && (
          <form onSubmit={submitDisable} className="mt-3 max-w-xs">
            <p className="text-sm mb-2">
              To disable, enter a current 6-digit code from your authenticator:
            </p>
            <Field label="Code" required help="Disabling two-factor authentication requires a current authenticator code as a safety check.">
              <Input
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
              />
            </Field>
            {disableErr && <div role="alert" className="text-sm text-danger mt-1">{disableErr}</div>}
            <Button
              type="submit"
              variant="danger"
              className="mt-2"
              disabled={disable.isPending || disableCode.length !== 6}
            >
              {disable.isPending ? "Disabling…" : "Disable two-factor"}
            </Button>
          </form>
        )}
      </CardBody>
    </Card>
  );
}
