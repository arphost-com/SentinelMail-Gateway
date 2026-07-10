import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:       "rgb(var(--bg) / <alpha-value>)",
        surface:  "rgb(var(--surface) / <alpha-value>)",
        muted:    "rgb(var(--muted) / <alpha-value>)",
        border:   "rgb(var(--border) / <alpha-value>)",
        fg:       "rgb(var(--fg) / <alpha-value>)",
        subtle:   "rgb(var(--subtle) / <alpha-value>)",
        accent:   "rgb(var(--accent) / <alpha-value>)",
        accentFg: "rgb(var(--accent-fg) / <alpha-value>)",
        danger:   "rgb(var(--danger) / <alpha-value>)",
        warning:  "rgb(var(--warning) / <alpha-value>)",
        success:  "rgb(var(--success) / <alpha-value>)",
        focus:    "rgb(var(--focus) / <alpha-value>)",
      },
      fontSize: {
        // Bumped up in the "large" theme via CSS var override.
        base: ["var(--text-base, 1rem)", { lineHeight: "1.5" }],
      },
      borderRadius: {
        DEFAULT: "var(--radius, 0.375rem)",
      },
    },
  },
  plugins: [],
} satisfies Config;
