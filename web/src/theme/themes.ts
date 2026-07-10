export type ThemeId = "light" | "dark" | "hc-light" | "hc-dark" | "cb-safe" | "large";

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  description: string;
}

export const THEMES: ThemeMeta[] = [
  { id: "light", label: "Light", description: "Default light theme." },
  { id: "dark", label: "Dark", description: "Default dark theme." },
  { id: "hc-light", label: "High Contrast Light", description: "Maximum-contrast variant for low-vision users." },
  { id: "hc-dark", label: "High Contrast Dark", description: "Maximum-contrast dark variant." },
  { id: "cb-safe", label: "Colorblind Safe", description: "Avoids red/green pairs; uses blue + orange." },
  { id: "large", label: "Large Text", description: "Larger base font + softer borders." },
];

export type Motion = "auto" | "reduced";
