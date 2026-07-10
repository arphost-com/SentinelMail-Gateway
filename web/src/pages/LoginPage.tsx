import { FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";

export function LoginPage() {
  const { me, login, verifyMFA } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // MFA second step
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");

  if (me) {
    const dest = (location.state as { from?: string } | null)?.from ?? "/dashboard";
    return <Navigate to={dest} replace />;
  }

  async function onPasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const ch = await login(email.trim(), password);
      if (ch) {
        // MFA second step required.
        setChallenge(ch.challenge);
      } else {
        navigate("/dashboard", { replace: true });
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  async function onMFASubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await verifyMFA(challenge!, code.trim());
      navigate("/dashboard", { replace: true });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "verification failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-3">
            <img src="/favicon.svg" alt="" width={40} height={40} className="shrink-0" />
            <div>
              <CardTitle>SentinelMail Gateway</CardTitle>
              <p className="text-sm text-subtle mt-1">
                {challenge ? "Enter your authenticator code." : "Sign in to continue."}
              </p>
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {!challenge ? (
            <form onSubmit={onPasswordSubmit} className="flex flex-col gap-3" noValidate>
              <label className="text-sm">
                <span className="block mb-1">Email</span>
                <Input
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  aria-invalid={err ? "true" : undefined}
                />
              </label>
              <label className="text-sm">
                <span className="block mb-1">Password</span>
                <Input
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  aria-invalid={err ? "true" : undefined}
                />
              </label>
              {err && (
                <div role="alert" className="text-sm text-danger">
                  {err}
                </div>
              )}
              <Button type="submit" disabled={busy}>
                {busy ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          ) : (
            <form onSubmit={onMFASubmit} className="flex flex-col gap-3" noValidate>
              <label className="text-sm">
                <span className="block mb-1">6-digit code</span>
                <Input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoFocus
                  aria-invalid={err ? "true" : undefined}
                />
              </label>
              {err && (
                <div role="alert" className="text-sm text-danger">
                  {err}
                </div>
              )}
              <div className="flex gap-2">
                <Button type="submit" disabled={busy || code.length !== 6}>
                  {busy ? "Verifying…" : "Verify"}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setChallenge(null);
                    setCode("");
                    setErr(null);
                  }}
                >
                  Cancel
                </Button>
              </div>
              <p className="text-xs text-subtle">
                The challenge expires in 5 minutes — cancel and re-enter your password if it does.
              </p>
            </form>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
