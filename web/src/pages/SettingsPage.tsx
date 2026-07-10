import { useState } from "react";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { AccountTab } from "./settings/AccountTab";
import { useTheme } from "../theme/ThemeProvider";
import { THEMES, type ThemeId } from "../theme/themes";
import clsx from "clsx";

type Tab = "appearance" | "account";

const TABS: { id: Tab; label: string }[] = [
  { id: "appearance", label: "Appearance" },
  { id: "account", label: "Account" },
];

/**
 * /settings is "User settings" — personal preferences for every signed-in
 * user, including admins. System / Org / MSP configuration lives under
 * /system-settings, /org-settings, /msp-settings.
 */
export function SettingsPage() {
  const [tab, setTab] = useState<Tab>("appearance");

  return (
    <div>
      <div className="mb-5 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">User settings</h1>
          <p className="mt-1 max-w-3xl text-sm text-subtle">
            Personal preferences for your account, including appearance, phishing alert cadence, password, and MFA.
          </p>
        </div>
      </div>

      <div role="tablist" aria-label="User settings tabs" className="mb-4 flex gap-1 rounded border border-border bg-muted p-1">
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              type="button"
              aria-selected={active}
              aria-controls={`tab-panel-${t.id}`}
              id={`tab-${t.id}`}
              onClick={() => setTab(t.id)}
              className={clsx(
                "rounded px-4 py-2 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focus",
                active
                  ? "bg-surface text-fg font-semibold shadow-sm"
                  : "text-subtle hover:bg-surface/70 hover:text-fg"
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={`tab-panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "appearance" && <AppearanceTab />}
        {tab === "account" && <AccountTab />}
      </div>
    </div>
  );
}

function AppearanceTab() {
  const { theme, setTheme, motion, setMotion } = useTheme();
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Theme</CardTitle>
        </CardHeader>
        <CardBody>
          <fieldset>
            <legend className="text-sm font-medium mb-2 sr-only">Theme</legend>
            <div className="grid gap-2 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
              {THEMES.map((t) => (
                <label
                  key={t.id}
                  className={clsx(
                    "flex min-h-[7rem] cursor-pointer items-start gap-3 rounded border p-3 transition-colors hover:bg-muted",
                    theme === t.id ? "border-accent bg-muted shadow-sm" : "border-border bg-surface"
                  )}
                >
                  <input
                    type="radio"
                    name="theme"
                    value={t.id}
                    checked={theme === t.id}
                    onChange={() => setTheme(t.id as ThemeId)}
                    className="mt-1"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium">{t.label}</span>
                    <span className="block text-xs text-subtle">{t.description}</span>
                    <span className="mt-3 grid grid-cols-5 gap-1" aria-hidden="true">
                      <span className="h-5 rounded border border-border bg-bg" />
                      <span className="h-5 rounded border border-border bg-surface" />
                      <span className="h-5 rounded bg-muted" />
                      <span className="h-5 rounded bg-accent" />
                      <span className="h-5 rounded bg-danger" />
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Motion</CardTitle>
        </CardHeader>
        <CardBody>
          <fieldset>
            <legend className="text-sm font-medium mb-2 sr-only">Motion</legend>
            <div className="grid gap-2 md:grid-cols-2">
              <label className={clsx("flex cursor-pointer items-center gap-3 rounded border p-3", motion === "auto" ? "border-accent bg-muted" : "border-border")}>
                <input type="radio" name="motion" checked={motion === "auto"} onChange={() => setMotion("auto")} />
                <span>
                  <span className="block font-medium">Follow system</span>
                  <span className="block text-xs text-subtle">Use the browser or operating system motion preference.</span>
                </span>
              </label>
              <label className={clsx("flex cursor-pointer items-center gap-3 rounded border p-3", motion === "reduced" ? "border-accent bg-muted" : "border-border")}>
                <input type="radio" name="motion" checked={motion === "reduced"} onChange={() => setMotion("reduced")} />
                <span>
                  <span className="block font-medium">Reduce motion</span>
                  <span className="block text-xs text-subtle">Minimize transitions and animations throughout the app.</span>
                </span>
              </label>
            </div>
          </fieldset>
        </CardBody>
      </Card>
    </div>
  );
}
