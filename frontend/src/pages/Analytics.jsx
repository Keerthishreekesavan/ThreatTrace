import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { api } from "../api";
import { Card, ChartTooltip, EmptyState, ErrorNote, RiskBadge, Spinner } from "../components/ui";
import { DETECTION_LABELS, chartTheme } from "../theme";

export default function Analytics({ datasetId, theme }) {
  const [analytics, setAnalytics] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const t = useMemo(() => chartTheme(), [theme]);

  useEffect(() => {
    if (!datasetId) return;
    setLoading(true);
    api
      .getAnalytics(datasetId)
      .then((data) => {
        setAnalytics(data);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [datasetId]);

  if (!datasetId) return <EmptyState>Upload a log file to get started.</EmptyState>;
  if (loading) return <Spinner />;
  if (error) return <ErrorNote error={error} />;
  if (!analytics) return null;

  const topIps = analytics.top_malicious_ips.map((a) => ({
    ip: a.source_ip,
    risk: a.risk_score,
    classification: a.classification,
    country: a.country,
  }));

  const categories = Object.entries(analytics.attack_categories)
    .map(([type, count]) => ({ label: DETECTION_LABELS[type] || type, count }))
    .sort((a, b) => b.count - a.count);

  const axisProps = {
    stroke: t.baseline,
    tick: { fill: t.muted, fontSize: 11 },
    tickLine: false,
  };

  return (
    <div className="space-y-6">
      {/* Magnitude comparison -> horizontal bar in one sequential hue. Risk
          severity is conveyed by the adjacent badge (icon + label), so the
          bar's color doesn't have to carry it. */}
      <Card title="Top malicious IPs" subtitle="By deterministic 0-100 risk score">
        {topIps.length === 0 ? (
          <EmptyState>No flagged IPs.</EmptyState>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(200, topIps.length * 34)}>
            <BarChart
              data={topIps}
              layout="vertical"
              margin={{ top: 4, right: 40, bottom: 4, left: 8 }}
            >
              <CartesianGrid stroke={t.gridline} horizontal={false} />
              <XAxis type="number" domain={[0, 100]} {...axisProps} />
              <YAxis
                type="category"
                dataKey="ip"
                width={116}
                tick={{ fill: t.textSecondary, fontSize: 11 }}
                tickLine={false}
                stroke={t.baseline}
              />
              <Tooltip
                content={<ChartTooltip />}
                cursor={{ fill: t.gridline, fillOpacity: 0.4 }}
              />
              <Bar
                dataKey="risk"
                name="Risk score"
                fill={t.sequential}
                radius={[0, 4, 4, 0]}
                barSize={14}
                isAnimationActive={false}
                label={{
                  position: "right",
                  fill: t.textSecondary,
                  fontSize: 11,
                }}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </Card>

      <Card title="Attack categories" subtitle="Total detections per threat class">
        {categories.length === 0 ? (
          <EmptyState>No detections fired.</EmptyState>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(180, categories.length * 40)}>
            <BarChart
              data={categories}
              layout="vertical"
              margin={{ top: 4, right: 40, bottom: 4, left: 8 }}
            >
              <CartesianGrid stroke={t.gridline} horizontal={false} />
              <XAxis type="number" allowDecimals={false} {...axisProps} />
              <YAxis
                type="category"
                dataKey="label"
                width={150}
                tick={{ fill: t.textSecondary, fontSize: 11 }}
                tickLine={false}
                stroke={t.baseline}
              />
              <Tooltip
                content={<ChartTooltip />}
                cursor={{ fill: t.gridline, fillOpacity: 0.4 }}
              />
              <Bar
                dataKey="count"
                name="Detections"
                fill={t.sequential}
                radius={[0, 4, 4, 0]}
                barSize={16}
                isAnimationActive={false}
                label={{ position: "right", fill: t.textSecondary, fontSize: 11 }}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </Card>

      {/* Many classes with long names -> a table is the right form, not more
          colors. Approximate country attribution from the bundled offline
          GeoIP table. */}
      <Card
        title="Geographic distribution"
        subtitle="Approximate attacker origin from the bundled offline GeoIP table"
      >
        {analytics.geographic_distribution.length === 0 ? (
          <EmptyState>No geolocated alerts.</EmptyState>
        ) : (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wide text-ink-muted">
                <th className="pb-2 font-medium">Country</th>
                <th className="pb-2 text-right font-medium">Flagged IPs</th>
                <th className="pb-2 text-right font-medium">Avg risk</th>
                <th className="pb-2 pl-4 font-medium">Share</th>
              </tr>
            </thead>
            <tbody>
              {analytics.geographic_distribution.map((row) => {
                const max = analytics.geographic_distribution[0].alert_count;
                return (
                  <tr key={row.country} style={{ borderTop: "1px solid var(--gridline)" }}>
                    <td className="py-2 text-ink-primary">{row.country}</td>
                    <td className="tabular py-2 text-right text-ink-secondary">
                      {row.alert_count}
                    </td>
                    <td className="tabular py-2 text-right text-ink-secondary">
                      {row.avg_risk_score}
                    </td>
                    <td className="w-40 py-2 pl-4">
                      <div
                        className="h-3 overflow-hidden rounded-sm"
                        style={{ background: "var(--gridline)" }}
                      >
                        <div
                          className="h-full rounded-sm"
                          style={{
                            width: `${(row.alert_count / max) * 100}%`,
                            background: t.sequential,
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>

      <Card
        title="Behavioural anomalies"
        subtitle="IPs whose Isolation Forest anomaly score is 50% or higher"
      >
        {analytics.behaviour_anomalies.length === 0 ? (
          <EmptyState>No strong behavioural anomalies in this dataset.</EmptyState>
        ) : (
          <ul className="space-y-3">
            {analytics.behaviour_anomalies.map((a) => (
              <li
                key={a.id}
                className="flex flex-wrap items-center gap-x-4 gap-y-1.5"
                style={{ borderTop: "1px solid var(--gridline)", paddingTop: "0.75rem" }}
              >
                <span className="font-mono text-xs text-ink-primary">{a.source_ip}</span>
                <RiskBadge classification={a.classification} score={a.risk_score} />
                <span className="tabular text-xs text-ink-secondary">
                  anomaly {Math.round((a.components.behavior_anomaly || 0) * 100)}%
                </span>
                <span className="text-xs text-ink-secondary">{a.threat}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
