import { createContext, useCallback, useContext, useEffect, useMemo, useState, ReactNode } from "react";
import { api, ApiError } from "../api/client";

export interface Me {
  user_id: string;
  organization_id: string;
  email: string;
  role: string;
  impersonating?: boolean;
  impersonator_email?: string;
}

interface MFAChallenge {
  challenge: string;
  expires_at: string;
}

interface AuthContextValue {
  me: Me | null;
  loading: boolean;
  error: string | null;
  // Returns null on full login OR an MFA challenge if the user has TOTP
  // enrolled. Caller then prompts for a code and calls verifyMFA.
  login: (email: string, password: string) => Promise<MFAChallenge | null>;
  verifyMFA: (challenge: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.get<Me>("/me");
      setMe(data);
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setMe(null);
      } else {
        setError(e instanceof Error ? e.message : "auth check failed");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const login = useCallback(
    async (email: string, password: string): Promise<MFAChallenge | null> => {
      setError(null);
      const resp = await api.post<{ status: string; challenge?: string; expires_at?: string }>(
        "/auth/login",
        { email, password }
      );
      if (resp.status === "mfa_required" && resp.challenge && resp.expires_at) {
        return { challenge: resp.challenge, expires_at: resp.expires_at };
      }
      await refresh();
      return null;
    },
    [refresh]
  );

  const verifyMFA = useCallback(
    async (challenge: string, code: string) => {
      setError(null);
      await api.post("/auth/mfa/verify", { challenge, code });
      await refresh();
    },
    [refresh]
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo(
    () => ({ me, loading, error, login, verifyMFA, logout, refresh }),
    [me, loading, error, login, verifyMFA, logout, refresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
