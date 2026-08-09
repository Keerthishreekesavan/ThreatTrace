import Icon from "./Icon";
import { RISK_COLORS, RISK_ICONS, riskBand } from "../theme";

/* ── Surfaces ─────────────────────────────────────────────────────────────── */

export function Card({ title, subtitle, children, actions, className = "", wash = false }) {
  return (
    <section className={`panel ${wash ? "brand-wash" : ""} p-5 ${className}`}>
      {(title || actions) && (
        <header className="mb-4 flex items-start justify-between gap-4">
          <div>
            {title && (
              <h2 className="text-[13px] font-semibold tracking-tight text-ink-primary">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-1 text-xs text-ink-secondary">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

/* ── Metric cards ─────────────────────────────────────────────────────────── */

/* A tinted metric tile. `tone` selects the accent; the icon and label carry the
   meaning, so the tint is decoration and never the only signal. */
export function MetricCard({ icon, label, value, hint, tone = "brand", hero = false }) {
  const tones = {
    brand: "var(--brand)",
    series1: "var(--series-1)",
    series3: "var(--series-3)",
    series5: "var(--series-5)",
    critical: RISK_COLORS.Critical,
    warning: RISK_COLORS.Medium,
  };
  const c = tones[tone] || tones.brand;

  return (
    <div
      className="panel relative overflow-hidden p-5"
      style={{
        background: `linear-gradient(150deg, color-mix(in srgb, ${c} 12%, var(--surface)), var(--surface) 62%)`,
      }}
    >
      <div
        aria-hidden="true"
        className="absolute -right-6 -top-8 h-24 w-24 rounded-full"
        style={{ background: `color-mix(in srgb, ${c} 16%, transparent)`, filter: "blur(6px)" }}
      />
      <div className="relative">
        <div className="flex items-center gap-2">
          <span
            aria-hidden="true"
            className="grid h-8 w-8 place-items-center rounded-[10px]"
            style={{ background: `color-mix(in srgb, ${c} 18%, transparent)`, color: c }}
          >
            <Icon name={icon} size={16} />
          </span>
          <span className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            {label}
          </span>
        </div>
        <div
          className={`mt-3 font-semibold leading-none tracking-tight text-ink-primary ${
            hero ? "text-[40px]" : "text-[28px]"
          }`}
        >
          {value}
        </div>
        {hint && <div className="mt-2 text-xs text-ink-secondary">{hint}</div>}
      </div>
    </div>
  );
}

/* ── Radial meter ─────────────────────────────────────────────────────────── */

/* A single ratio against a limit, drawn as an arc. The fill carries severity;
   the track is a muted step of the same family so state reads across the whole
   arc. The numeric value is always printed inside, so the arc is reinforcement
   rather than the sole channel. */
export function RadialMeter({
  value,
  max = 100,
  label,
  sublabel,
  color,
  size = 190,
  thickness = 14,
}) {
  const pct = Math.max(0, Math.min(1, value / max));
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  // 270° sweep, opening at the bottom
  const sweep = 0.75;
  const fill = c * sweep * pct;
  const gap = c - c * sweep * pct;
  const band = color ? { color } : riskBand(value);
  const stroke = band.color;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-[225deg]">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="var(--sunken)"
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${c * sweep} ${c * (1 - sweep)}`}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={stroke}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${fill} ${gap}`}
            style={{ transition: "stroke-dasharray .5s ease" }}
          />
        </svg>
        <div className="absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[34px] font-semibold leading-none tracking-tight text-ink-primary">
              {typeof value === "number" ? Math.round(value) : value}
            </div>
            {label && (
              <div className="mt-1.5 text-[11px] font-semibold uppercase tracking-wider" style={{ color: stroke }}>
                {label}
              </div>
            )}
          </div>
        </div>
      </div>
      {sublabel && <p className="mt-2 text-center text-xs text-ink-secondary">{sublabel}</p>}
    </div>
  );
}

/* ── Risk severity ────────────────────────────────────────────────────────── */

/* Severity always ships as icon + text label + colour, never colour alone -
   the reserved status steps sit close together (serious vs warning measure
   ΔE 13.6), so the pairing is what makes them distinguishable. */
export function RiskBadge({ classification, score }) {
  const color = RISK_COLORS[classification] || "var(--text-muted)";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold"
      style={{
        color,
        background: `color-mix(in srgb, ${color} 14%, transparent)`,
        boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${color} 42%, transparent)`,
      }}
    >
      <span aria-hidden="true">{RISK_ICONS[classification]}</span>
      {classification}
      {score !== undefined && <span className="tabular opacity-90">{score}</span>}
    </span>
  );
}

/* ── Bars ─────────────────────────────────────────────────────────────────── */

/* Horizontal magnitude bar in one sequential hue, with the value direct-labeled
   so the length never has to be estimated. */
export function Bar({ label, value, max, display, color = "var(--seq-450)", labelWidth = "10rem" }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <li className="flex items-center gap-3">
      <span className="shrink-0 text-xs text-ink-secondary" style={{ width: labelWidth }}>
        {label}
      </span>
      <div className="h-2.5 flex-1 overflow-hidden rounded-full" style={{ background: "var(--sunken)" }}>
        <div
          className="h-full rounded-full"
          style={{ width: `${pct}%`, background: color, transition: "width .4s ease" }}
        />
      </div>
      <span className="tabular w-12 shrink-0 text-right text-xs font-medium text-ink-primary">
        {display ?? value}
      </span>
    </li>
  );
}

/* ── States ───────────────────────────────────────────────────────────────── */

export function Spinner({ label = "Loading…" }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12 text-sm text-ink-secondary">
      <span
        aria-hidden="true"
        className="h-3.5 w-3.5 animate-spin rounded-full border-2"
        style={{ borderColor: "var(--brand-ring)", borderTopColor: "var(--brand)" }}
      />
      {label}
    </div>
  );
}

export function ErrorNote({ error }) {
  if (!error) return null;
  const c = RISK_COLORS.Critical;
  return (
    <p
      role="alert"
      className="flex items-start gap-2 rounded-xl px-3.5 py-2.5 text-sm"
      style={{
        color: c,
        background: `color-mix(in srgb, ${c} 10%, transparent)`,
        boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${c} 38%, transparent)`,
      }}
    >
      <span aria-hidden="true">▲</span>
      {error}
    </p>
  );
}

export function EmptyState({ children, icon = "◎" }) {
  return (
    <div className="py-12 text-center">
      <div aria-hidden="true" className="text-2xl text-ink-muted opacity-60">
        {icon}
      </div>
      <p className="mt-2 text-sm text-ink-secondary">{children}</p>
    </div>
  );
}

/* ── Chart chrome ─────────────────────────────────────────────────────────── */

export function ChartTooltip({ active, payload, label, formatLabel }) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-xl px-3 py-2 text-xs"
      style={{
        background: "var(--raised)",
        boxShadow: "0 0 0 1px var(--border-ring), var(--shadow-pop)",
      }}
    >
      <div className="mb-1.5 font-semibold text-ink-primary">
        {formatLabel ? formatLabel(label) : label}
      </div>
      {payload
        .filter((entry) => entry.value)
        .map((entry) => (
          <div key={entry.name} className="flex items-center gap-2 text-ink-secondary">
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 rounded-sm"
              style={{ background: entry.color }}
            />
            <span>{entry.name}</span>
            <span className="tabular ml-auto pl-3 font-medium text-ink-primary">{entry.value}</span>
          </div>
        ))}
    </div>
  );
}

/* Identity is never colour-alone: every multi-series chart ships this. */
export function Legend({ items }) {
  return (
    <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-1.5 text-xs text-ink-secondary">
          <span
            aria-hidden="true"
            className="inline-block h-2.5 w-2.5 rounded-sm"
            style={{ background: item.color }}
          />
          {item.label}
        </li>
      ))}
    </ul>
  );
}

/* Segmented control used for chart bucket sizes and filters. */
export function Segmented({ options, value, onChange }) {
  return (
    <div
      className="inline-flex gap-0.5 rounded-lg p-0.5"
      style={{ background: "var(--sunken)" }}
      role="group"
    >
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            aria-pressed={active}
            className="focusable rounded-[6px] px-2.5 py-1 text-[11px] transition-colors"
            style={
              active
                ? { background: "var(--surface)", color: "var(--text-primary)", fontWeight: 600 }
                : { color: "var(--text-secondary)" }
            }
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
