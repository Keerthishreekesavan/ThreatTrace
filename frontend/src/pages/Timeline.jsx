import { useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { api } from "../api";
import {
  Card,
  ChartTooltip,
  EmptyState,
  ErrorNote,
  Legend,
  Segmented,
  Spinner,
} from "../components/ui";
import { DETECTION_LABELS, DETECTION_TYPES, chartTheme } from "../theme";

const BUCKET_OPTIONS = [
  { value: 5, label: "5m" },
  { value: 30, label: "30m" },
  { value: 60, label: "1h" },
  { value: 360, label: "6h" },
];

function formatBucket(value) {
  const d = new Date(value);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function Timeline({ datasetId, theme }) {
  const [bucketMinutes, setBucketMinutes] = useState(30);
  const [timeline, setTimeline] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const t = useMemo(() => chartTheme(), [theme]);

  useEffect(() => {
    if (!datasetId) return;
    setLoading(true);
    api
      .getTimeline(datasetId, bucketMinutes)
      .then((data) => {
        setTimeline(data);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [datasetId, bucketMinutes]);

  const { volumeData, detectionData, activeTypes } = useMemo(() => {
    if (!timeline) return { volumeData: [], detectionData: [], activeTypes: [] };

    const volume = timeline.points.map((p) => ({
      bucket: new Date(p.bucket).getTime(),
      events: p.total_events,
    }));

    const withDetections = timeline.points.filter(
      (p) => Object.keys(p.detection_counts).length > 0
    );
    const detections = withDetections.map((p) => ({
      bucket: new Date(p.bucket).getTime(),
      ...Object.fromEntries(DETECTION_TYPES.map((type) => [type, p.detection_counts[type] || 0])),
    }));

    // Series color follows the detection type, never its rank - a type that
    // never fires simply isn't drawn, and the rest keep their slots.
    const active = DETECTION_TYPES.filter((type) =>
      withDetections.some((p) => p.detection_counts[type])
    );

    return { volumeData: volume, detectionData: detections, activeTypes: active };
  }, [timeline]);

  if (!datasetId) return <EmptyState>Upload a log file to get started.</EmptyState>;
  if (loading) return <Spinner />;
  if (error) return <ErrorNote error={error} />;
  if (!timeline || volumeData.length === 0) {
    return <EmptyState>This dataset has no parseable timestamps to plot.</EmptyState>;
  }

  const axisProps = {
    stroke: t.baseline,
    tick: { fill: t.muted, fontSize: 11 },
    tickLine: false,
  };

  const bucketPicker = (
    <Segmented options={BUCKET_OPTIONS} value={bucketMinutes} onChange={setBucketMinutes} />
  );

  return (
    <div className="space-y-5">
      {/* Two measures at very different scales share this time axis, so they
          get two stacked charts rather than one dual-axis chart. */}
      <Card
        title="Event volume over time"
        subtitle={`Total events per ${bucketMinutes}-minute bucket`}
        actions={bucketPicker}
      >
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={volumeData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            {/* Gradient is a fade of the single series hue toward the surface -
                decoration on one colour, not a second encoding. */}
            <defs>
              <linearGradient id="volumeFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={t.sequential} stopOpacity={0.42} />
                <stop offset="100%" stopColor={t.sequential} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={t.gridline} vertical={false} />
            <XAxis
              dataKey="bucket"
              type="number"
              scale="time"
              domain={["dataMin", "dataMax"]}
              tickFormatter={formatBucket}
              minTickGap={48}
              {...axisProps}
            />
            <YAxis width={44} {...axisProps} />
            <Tooltip
              content={<ChartTooltip formatLabel={formatBucket} />}
              cursor={{ stroke: t.baseline, strokeWidth: 1 }}
            />
            <Area
              type="monotone"
              dataKey="events"
              name="Events"
              stroke={t.sequential}
              strokeWidth={2}
              fill="url(#volumeFill)"
              dot={false}
              isAnimationActive={false}
              activeDot={{ r: 4, strokeWidth: 2, stroke: t.surface }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      <Card
        title="Detections over time by type"
        subtitle="When each detector fired - use this to correlate an attack's progression"
      >
        {detectionData.length === 0 ? (
          <EmptyState>No detections have a timestamped window in this dataset.</EmptyState>
        ) : (
          <>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={detectionData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid stroke={t.gridline} vertical={false} />
                <XAxis
                  dataKey="bucket"
                  type="number"
                  scale="time"
                  domain={["dataMin", "dataMax"]}
                  tickFormatter={formatBucket}
                  minTickGap={48}
                  {...axisProps}
                />
                <YAxis width={44} allowDecimals={false} {...axisProps} />
                <Tooltip
                  content={<ChartTooltip formatLabel={formatBucket} />}
                  cursor={{ fill: t.gridline, fillOpacity: 0.4 }}
                />
                {activeTypes.map((type) => (
                  <Bar
                    key={type}
                    dataKey={type}
                    name={DETECTION_LABELS[type]}
                    stackId="detections"
                    fill={t.series[type]}
                    /* 2px surface gap between stacked segments */
                    stroke={t.surface}
                    strokeWidth={2}
                    barSize={18}
                    isAnimationActive={false}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
            <Legend
              items={activeTypes.map((type) => ({
                label: DETECTION_LABELS[type],
                color: t.series[type],
              }))}
            />
          </>
        )}
      </Card>
    </div>
  );
}
