/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Chart chrome & ink roles are driven by CSS custom properties
        // (see src/index.css) so light/dark swap in exactly one place.
        surface: "var(--surface)",
        raised: "var(--raised)",
        sunken: "var(--sunken)",
        plane: "var(--plane)",
        brand: "var(--brand)",
        ink: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        hairline: "var(--gridline)",
        baseline: "var(--baseline)",
        // Status palette - fixed, never themed. Reserved for risk severity.
        status: {
          good: "#0ca30c",
          warning: "#fab219",
          serious: "#ec835a",
          critical: "#d03b3b",
        },
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "sans-serif"],
      },
    },
  },
  plugins: [],
};
