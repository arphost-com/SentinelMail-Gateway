import { createContext, useCallback, useContext, useEffect, useMemo, useState, ReactNode } from "react";
import { THEMES, type Motion, type ThemeId } from "./themes";

interface ThemeContextValue {
  theme: ThemeId;
  setTheme: (t: ThemeId) => void;
  motion: Motion;
  setMotion: (m: Motion) => void;
}

const STORAGE_KEY = "smg.theme";
const MOTION_KEY = "smg.motion";

const ThemeContext = createContext<ThemeContextValue | null>(null);

function initial<T extends string>(key: string, fallback: T, allowed: readonly T[]): T {
  try {
    const v = localStorage.getItem(key);
    if (v && (allowed as readonly string[]).includes(v)) return v as T;
  } catch {
    /* ignore — private browsing, etc. */
  }
  return fallback;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(() =>
    initial<ThemeId>(STORAGE_KEY, prefersDark() ? "dark" : "light", THEMES.map((t) => t.id))
  );
  const [motion, setMotionState] = useState<Motion>(() =>
    initial<Motion>(MOTION_KEY, "auto", ["auto", "reduced"])
  );

  const setTheme = useCallback((t: ThemeId) => {
    setThemeState(t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      /* ignore */
    }
  }, []);

  const setMotion = useCallback((m: Motion) => {
    setMotionState(m);
    try {
      localStorage.setItem(MOTION_KEY, m);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (motion === "reduced") {
      document.documentElement.setAttribute("data-motion", "reduced");
    } else {
      document.documentElement.removeAttribute("data-motion");
    }
  }, [motion]);

  const value = useMemo(() => ({ theme, setTheme, motion, setMotion }), [theme, setTheme, motion, setMotion]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside ThemeProvider");
  return ctx;
}

function prefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
