/* Chart color roles, resolved from the CSS custom properties in index.css so
   charts stay written against roles rather than raw hex, and light/dark swap
   in one place.

   Recharts needs concrete color strings rather than `var(...)` in some props,
   so we read the computed values off :root once per theme change. */

export const DETECTION_TYPES = [
  "brute_force",
  "credential_spray",
  "port_scan",
  "endpoint_probe",
  "unknown_anomaly",
];

export const DETECTION_LABELS = {
  brute_force: "Brute force",
  credential_spray: "Credential spraying",
  port_scan: "Port scanning",
  endpoint_probe: "Endpoint probing",
  unknown_anomaly: "Behavioural anomaly",
};

/* Fixed slot order - a series' color follows the entity, never its rank, so a
   filtered-out type never repaints the survivors. */
const SERIES_SLOTS = {
  brute_force: "--series-1",
  credential_spray: "--series-2",
  port_scan: "--series-3",
  endpoint_probe: "--series-4",
  unknown_anomaly: "--series-5",
};

/* Risk severity uses the reserved status palette (fixed, never themed) and is
   always paired with a text label + icon so color never carries meaning
   alone. */
export const RISK_COLORS = {
  Critical: "#d03b3b",
  High: "#ec835a",
  Medium: "#fab219",
  Low: "#0ca30c",
};

export const RISK_ICONS = {
  Critical: "◉",
  High: "▲",
  Medium: "◆",
  Low: "●",
};

export const RISK_LEVELS = ["Critical", "High", "Medium", "Low"];

function cssVar(name) {
  if (typeof window === "undefined") return "#888888";
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888888";
}

export function chartTheme() {
  return {
    surface: cssVar("--surface"),
    raised: cssVar("--raised"),
    sunken: cssVar("--sunken"),
    textPrimary: cssVar("--text-primary"),
    textSecondary: cssVar("--text-secondary"),
    muted: cssVar("--text-muted"),
    gridline: cssVar("--gridline"),
    baseline: cssVar("--baseline"),
    sequential: cssVar("--seq-450"),
    sequentialLight: cssVar("--seq-250"),
    /* Chrome accent - nav, buttons, decorative washes. Never a data encoding. */
    brand: cssVar("--brand"),
    series: Object.fromEntries(
      Object.entries(SERIES_SLOTS).map(([key, slot]) => [key, cssVar(slot)])
    ),
  };
}

/* Risk bands, ordered low → critical, for meter fills. The meter's unfilled
   track is a lighter step of the *same* ramp so state reads across the whole
   arc rather than only at the tip. */
export function riskBand(score) {
  if (score >= 80) return { label: "Critical", color: RISK_COLORS.Critical };
  if (score >= 60) return { label: "High", color: RISK_COLORS.High };
  if (score >= 40) return { label: "Medium", color: RISK_COLORS.Medium };
  return { label: "Low", color: RISK_COLORS.Low };
}
