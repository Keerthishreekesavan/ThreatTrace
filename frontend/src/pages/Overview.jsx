import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import {
  Bar,
  Card,
  EmptyState,
  ErrorNote,
  MetricCard,
  RadialMeter,
  RiskBadge,
  Spinner,
} from "../components/ui";
import { DETECTION_LABELS, RISK_COLORS, RISK_LEVELS, chartTheme } from "../theme";

export default function Overview({ datasetId, theme }) {
  const [overview, setOverview] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const t = useMemo(() => chartTheme(), [theme]);

  useEffect(() => {
    if (!datasetId) return;
    setLoading(true);
    Promise.all([api.getOverview(datasetId), api.getAlerts(datasetId)])
      .then(([o, a]) => {
        setOverview(o);
        setAlerts(a);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [datasetId]);

  if (!datasetId) return <EmptyState icon="↑">Upload a log file to get started.</EmptyState>;
  if (loading) return <Spinner label="Loading analysis…" />;
  if (error) return <ErrorNote error={error} />;
  if (!overview) return null;

  const totalAlerts = RISK_LEVELS.reduce(
    (sum, l) => sum + (overview.risk_distribution[l] || 0),
    0
  );
  const detectionEntries = Object.entries(overview.detection_type_counts).sort(
    (a, b) => b[1] - a[1]
  );
  const maxDetection = detectionEntries[0]?.[1] || 0;

  // The dashboard's single headline figure: the worst risk score present. It's a
  // ratio against a fixed 0-100 limit, so a radial meter is the right form.
  const peakRisk = alerts.length ? alerts[0].risk_score : 0;
  const elevated =
    (overview.risk_distribution.Critical || 0) + (overview.risk_distribution.High || 0);

  return (
    <div className="space-y-5">
      {/* Hero: the peak risk meter beside the KPI grid. */}
      <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
        <Card wash className="flex flex-col items-center justify-center">
          <RadialMeter
            value={peakRisk}
            label={alerts.length ? alerts[0].classification : "None"}
            sublabel={
              alerts.length
                ? `Highest risk score in this dataset · ${alerts[0].source_ip}`
                : "No IPs were flagged"
            }
          />
        </Card>

        <div className="grid gap-5 sm:grid-cols-2">
          <MetricCard
            icon="alert"
            tone="critical"
            label="Critical alerts"
            value={overview.critical_alerts}
            hint="Risk score 80 or above"
          />
          <MetricCard
            icon="shield"
            tone="series5"
            label="Threats detected"
            value={overview.threats_detected}
            hint={`${detectionEntries.length} of 5 detectors fired`}
          />
          <MetricCard
            icon="layers"
            tone="series1"
            label="Events analyzed"
            value={overview.total_events.toLocaleString()}
          />
          <MetricCard
            icon="globe"
            tone="series3"
            label="Unique source IPs"
            value={overview.unique_source_ips.toLocaleString()}
            hint={`${elevated} at high or critical risk`}
          />
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Part-to-whole across an ordered severity scale: one stacked bar in the
            reserved status colours, each segment separated by a surface gap and
            directly labeled below. */}
        <Card
          title="Risk distribution"
          subtitle={`${totalAlerts} flagged source IP${totalAlerts === 1 ? "" : "s"} by severity`}
        >
          {totalAlerts === 0 ? (
            <EmptyState>No IPs were flagged in this dataset.</EmptyState>
          ) : (
            <>
              <div
                className="flex h-9 w-full overflow-hidden rounded-lg"
                role="img"
                aria-label="Risk distribution by severity"
              >
                {RISK_LEVELS.map((level) => {
                  const count = overview.risk_distribution[level] || 0;
                  if (!count) return null;
                  return (
                    <div
                      key={level}
                      title={`${level}: ${count}`}
                      style={{
                        width: `${(count / totalAlerts) * 100}%`,
                        background: RISK_COLORS[level],
                        marginRight: 2,
                      }}
                    />
                  );
                })}
              </div>
              <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                {RISK_LEVELS.map((level) => (
                  <div key={level}>
                    <dt className="mb-1.5">
                      <RiskBadge classification={level} />
                    </dt>
                    <dd className="text-2xl font-semibold tracking-tight text-ink-primary">
                      {overview.risk_distribution[level] || 0}
                    </dd>
                  </div>
                ))}
              </dl>
            </>
          )}
        </Card>

        {/* Magnitude comparison across a few ordered categories: horizontal bars
            in one sequential hue, values direct-labeled. */}
        <Card title="Detections by type" subtitle="How many times each detector fired">
          {detectionEntries.length === 0 ? (
            <EmptyState>No detections fired for this dataset.</EmptyState>
          ) : (
            <ul className="space-y-3">
              {detectionEntries.map(([type, count]) => (
                <Bar
                  key={type}
                  label={DETECTION_LABELS[type] || type}
                  value={count}
                  max={maxDetection}
                  color={t.sequential}
                />
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Highest-risk source IPs" subtitle="Ordered by risk score for triage">
        {alerts.length === 0 ? (
          <EmptyState>No alerts to triage.</EmptyState>
        ) : (
          <div className="scroll-x -mx-1 px-1">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-[11px] uppercase tracking-wider text-ink-muted">
                  <th className="pb-2.5 font-semibold">Source IP</th>
                  <th className="pb-2.5 font-semibold">Risk</th>
                  <th className="pb-2.5 font-semibold">Threat</th>
                  <th className="pb-2.5 font-semibold">Origin</th>
                  <th className="pb-2.5 text-right font-semibold">Events</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 10).map((alert) => (
                  <tr key={alert.id} style={{ borderTop: "1px solid var(--gridline)" }}>
                    <td className="py-2.5 font-mono text-xs text-ink-primary">
                      {alert.source_ip}
                    </td>
                    <td className="py-2.5">
                      <RiskBadge
                        classification={alert.classification}
                        score={alert.risk_score}
                      />
                    </td>
                    <td className="py-2.5 text-ink-secondary">{alert.threat}</td>
                    <td className="py-2.5 text-xs text-ink-secondary">
                      {alert.country || "Unknown"}
                    </td>
                    <td className="tabular py-2.5 text-right text-ink-secondary">
                      {alert.event_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
