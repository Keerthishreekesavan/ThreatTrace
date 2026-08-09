import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import Icon from "../components/Icon";
import {
  Card,
  EmptyState,
  ErrorNote,
  RiskBadge,
  Segmented,
  Spinner,
} from "../components/ui";
import { DETECTION_LABELS, RISK_COLORS, RISK_LEVELS, chartTheme } from "../theme";

const RISK_COMPONENT_LABELS = {
  threat_severity: "Threat severity (40%)",
  behavior_anomaly: "Behaviour anomaly (30%)",
  frequency: "Frequency (15%)",
  confidence: "Confidence (15%)",
};

/* The alerts list carries a human-readable threat string rather than the raw
   detector key, so the card glyph is derived from it. */
function threatIcon(threat = "") {
  const t = threat.toLowerCase();
  // "Multiple threat indicators" alerts list several threats, so test the more
  // specific patterns first and let the generic warning glyph be the fallback.
  if (t.includes("multiple")) return "alert";
  if (t.includes("spray")) return "users";
  if (t.includes("scan") || t.includes("reconnaissance")) return "radar";
  if (t.includes("probing") || t.includes("endpoint")) return "search";
  if (t.includes("anomaly")) return "pulse";
  if (t.includes("brute")) return "lock";
  return "alert";
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/* ── Flagged-IP card ──────────────────────────────────────────────────────────
   The card is the primary control on this page, so it's a real <button> with a
   visible hover/focus lift. Its gradient is tinted by *severity*, which the
   badge also states in words - the tint reinforces, it never carries the
   meaning alone.                                                             */
function IpCard({ alert, onSelect }) {
  const c = RISK_COLORS[alert.classification] || "var(--brand)";
  return (
    <button
      type="button"
      onClick={() => onSelect(alert.source_ip)}
      className="focusable group relative overflow-hidden rounded-2xl p-5 text-left transition-transform duration-150 hover:-translate-y-0.5"
      style={{
        background: `linear-gradient(155deg, color-mix(in srgb, ${c} 14%, var(--surface)), var(--surface) 68%)`,
        boxShadow: `0 0 0 1px var(--border-ring), var(--shadow-card)`,
      }}
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -right-8 -top-10 h-28 w-28 rounded-full opacity-70 transition-opacity group-hover:opacity-100"
        style={{ background: `color-mix(in srgb, ${c} 20%, transparent)`, filter: "blur(10px)" }}
      />

      <div className="relative">
        <div className="flex items-start justify-between gap-3">
          <span
            aria-hidden="true"
            className="grid h-9 w-9 place-items-center rounded-xl"
            style={{ background: `color-mix(in srgb, ${c} 20%, transparent)`, color: c }}
          >
            <Icon name={threatIcon(alert.threat)} size={17} />
          </span>
          <RiskBadge classification={alert.classification} score={alert.risk_score} />
        </div>

        <div className="mt-3.5 font-mono text-[15px] font-semibold tracking-tight text-ink-primary">
          {alert.source_ip}
        </div>
        <p className="mt-1 line-clamp-2 text-[13px] leading-snug text-ink-secondary">
          {alert.threat}
        </p>

        <div
          className="mt-4 flex items-center justify-between border-t pt-3 text-[11px]"
          style={{ borderColor: "var(--gridline)" }}
        >
          <span className="text-ink-muted">
            {alert.country || "Unknown origin"} · <span className="tabular">{alert.event_count}</span> events
          </span>
          <span
            className="font-semibold opacity-0 transition-opacity group-hover:opacity-100"
            style={{ color: c }}
          >
            Investigate →
          </span>
        </div>
      </div>
    </button>
  );
}

export default function Investigation({ datasetId, theme }) {
  const [alerts, setAlerts] = useState([]);
  const [selectedIp, setSelectedIp] = useState(null);
  const [detail, setDetail] = useState(null);
  const [filter, setFilter] = useState("All");
  const [error, setError] = useState(null);
  const [listLoading, setListLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const t = useMemo(() => chartTheme(), [theme]);

  useEffect(() => {
    if (!datasetId) return;
    setListLoading(true);
    setSelectedIp(null);
    setDetail(null);
    api
      .getAlerts(datasetId)
      .then((list) => {
        setAlerts(list);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setListLoading(false));
  }, [datasetId]);

  useEffect(() => {
    if (!datasetId || !selectedIp) return;
    setDetailLoading(true);
    api
      .investigateIp(datasetId, selectedIp)
      .then((data) => {
        setDetail(data);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setDetailLoading(false));
  }, [datasetId, selectedIp]);

  if (!datasetId) return <EmptyState icon="↑">Upload a log file to get started.</EmptyState>;
  if (error) return <ErrorNote error={error} />;
  if (listLoading) return <Spinner label="Loading flagged IPs…" />;
  if (alerts.length === 0) {
    return <EmptyState>No IPs were flagged in this dataset, so there's nothing to investigate.</EmptyState>;
  }

  /* ── Grid (selection) view ───────────────────────────────────────────────── */
  if (!selectedIp) {
    const present = RISK_LEVELS.filter((l) => alerts.some((a) => a.classification === l));
    const options = [
      { value: "All", label: `All ${alerts.length}` },
      ...present.map((l) => ({
        value: l,
        label: `${l} ${alerts.filter((a) => a.classification === l).length}`,
      })),
    ];
    const shown = filter === "All" ? alerts : alerts.filter((a) => a.classification === filter);

    return (
      <div className="space-y-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-ink-primary">
              Select an IP to investigate
            </h2>
            <p className="mt-1 text-xs text-ink-secondary">
              {alerts.length} flagged source IP{alerts.length === 1 ? "" : "s"}, ordered by risk
              score. Click any card for its evidence, risk breakdown, and raw log lines.
            </p>
          </div>
          {options.length > 1 && (
            <Segmented options={options} value={filter} onChange={setFilter} />
          )}
        </div>

        {shown.length === 0 ? (
          <EmptyState>No IPs at this severity.</EmptyState>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {shown.map((alert) => (
              <IpCard key={alert.id} alert={alert} onSelect={setSelectedIp} />
            ))}
          </div>
        )}
      </div>
    );
  }

  /* ── Detail view ─────────────────────────────────────────────────────────── */
  const alert = detail?.alert;

  return (
    <div className="space-y-5">
      <button
        type="button"
        onClick={() => {
          setSelectedIp(null);
          setDetail(null);
        }}
        className="focusable inline-flex items-center gap-2 rounded-xl px-3 py-2 text-xs text-ink-secondary transition-colors hover:text-ink-primary"
        style={{ boxShadow: "inset 0 0 0 1px var(--border-ring)" }}
      >
        <Icon name="back" size={14} />
        All flagged IPs
      </button>

      {detailLoading && <Spinner label={`Loading ${selectedIp}…`} />}

      {alert && (
        <>
          <Card
            wash
            title={alert.threat}
            subtitle={`${alert.source_ip} · ${alert.country || "Unknown location"} · ${detail.total_events} events`}
            actions={<RiskBadge classification={alert.classification} score={alert.risk_score} />}
          >
            <p className="text-sm text-ink-secondary">{alert.reason}</p>

            <div className="mt-5 grid gap-5 lg:grid-cols-2">
              <div>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Evidence
                </h3>
                <ul className="mt-2 space-y-1.5">
                  {alert.evidence.map((line, i) => (
                    <li key={i} className="flex gap-2 text-[13px] text-ink-secondary">
                      <span aria-hidden="true" className="text-ink-muted">·</span>
                      {line}
                    </li>
                  ))}
                </ul>

                <h3 className="mt-5 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Recommended actions
                </h3>
                <ol className="mt-2 space-y-1.5">
                  {alert.recommendation.map((rec, i) => (
                    <li key={i} className="flex gap-2 text-[13px] text-ink-secondary">
                      <span className="tabular text-ink-muted">{i + 1}.</span>
                      {rec}
                    </li>
                  ))}
                </ol>
              </div>

              <div>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  Risk score breakdown
                </h3>
                <p className="mt-1 text-[11px] text-ink-muted">
                  Deterministic weighted sum · confidence {alert.confidence}%
                </p>
                <ul className="mt-3 space-y-2.5">
                  {Object.entries(RISK_COMPONENT_LABELS).map(([key, label]) => (
                    <li key={key} className="flex items-center gap-3">
                      <span className="w-44 shrink-0 text-[11px] text-ink-secondary">{label}</span>
                      <div
                        className="h-2.5 flex-1 overflow-hidden rounded-full"
                        style={{ background: "var(--sunken)" }}
                      >
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(alert.components[key] || 0) * 100}%`,
                            background: t.sequential,
                          }}
                        />
                      </div>
                      <span className="tabular w-10 text-right text-[11px] text-ink-primary">
                        {Math.round((alert.components[key] || 0) * 100)}%
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>

          {detail.attack_progression.length > 0 && (
            <Card title="Attack progression" subtitle="Detections in the order they occurred">
              <ol className="space-y-3">
                {detail.attack_progression.map((step, i) => (
                  <li key={i} className="flex gap-3">
                    <span
                      aria-hidden="true"
                      className="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-sm"
                      style={{ background: t.series[step.detection_type] }}
                    />
                    <div>
                      <div className="text-[13px] font-medium text-ink-primary">
                        {DETECTION_LABELS[step.detection_type] || step.detection_type}
                      </div>
                      <div className="tabular mt-0.5 text-[11px] text-ink-secondary">
                        {formatTime(step.window_start)} → {formatTime(step.window_end)} ·{" "}
                        {step.event_count} events · severity {Math.round(step.severity * 100)}%
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
          )}

          {detail.detections.length > 0 && (
            <Card
              title="Detection details"
              subtitle="Raw evidence recorded by each detector that fired"
            >
              <div className="space-y-4">
                {detail.detections.map((d) => (
                  <div key={d.id}>
                    <h4 className="text-[13px] font-medium text-ink-primary">
                      {DETECTION_LABELS[d.detection_type] || d.detection_type}
                    </h4>
                    <dl className="mt-1.5 grid gap-x-6 gap-y-1 sm:grid-cols-2">
                      {Object.entries(d.evidence).map(([key, value]) => (
                        <div key={key} className="flex gap-2 text-[11px]">
                          <dt className="text-ink-muted">{key.replace(/_/g, " ")}:</dt>
                          <dd className="text-ink-secondary">
                            {Array.isArray(value) ? value.join(", ") : String(value)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card
            title="Related events"
            subtitle={`Underlying log lines from this IP (showing ${detail.related_events.length} of ${detail.total_events})`}
          >
            <div className="scroll-x -mx-1 px-1">
              <table className="w-full text-left text-[11px]">
                <thead>
                  <tr className="uppercase tracking-wider text-ink-muted">
                    <th className="pb-2 font-semibold">Time</th>
                    <th className="pb-2 font-semibold">User</th>
                    <th className="pb-2 font-semibold">Event</th>
                    <th className="pb-2 font-semibold">Dest</th>
                    <th className="pb-2 font-semibold">Port</th>
                    <th className="pb-2 font-semibold">Path</th>
                    <th className="pb-2 text-right font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody className="tabular">
                  {detail.related_events.slice(0, 50).map((e) => (
                    <tr key={e.id} style={{ borderTop: "1px solid var(--gridline)" }}>
                      <td className="py-1.5 text-ink-secondary">{formatTime(e.timestamp)}</td>
                      <td className="py-1.5 text-ink-secondary">{e.username || "-"}</td>
                      <td className="py-1.5 text-ink-secondary">{e.event_type || "-"}</td>
                      <td className="py-1.5 font-mono text-ink-secondary">
                        {e.destination_ip || "-"}
                      </td>
                      <td className="py-1.5 text-ink-secondary">{e.port != null ? e.port : "-"}</td>
                      <td className="py-1.5 font-mono text-ink-secondary">
                        {e.request_path || "-"}
                      </td>
                      <td className="py-1.5 text-right text-ink-secondary">
                        {e.status_code != null ? e.status_code : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
