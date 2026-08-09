import { useEffect, useMemo, useState } from "react";

import { api } from "../api";
import Icon from "../components/Icon";
import { Card, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { RISK_COLORS } from "../theme";

const UNMAPPED = "__unmapped__";

/* Below this the mapper's own docs call the match unreliable, so the UI flags
   it for review rather than presenting it as settled. */
const REVIEW_THRESHOLD = 0.6;

function confidenceTone(confidence, source) {
  if (source === "manual") return { color: "var(--brand)", label: "Set by you" };
  if (confidence >= REVIEW_THRESHOLD) return { color: RISK_COLORS.Low, label: "Confident" };
  if (confidence > 0) return { color: RISK_COLORS.Medium, label: "Check this" };
  return { color: "var(--text-muted)", label: "Unmapped" };
}

export default function Schema({ datasetId, onReanalyzed }) {
  const [fields, setFields] = useState([]);
  const [rows, setRows] = useState([]);
  const [draft, setDraft] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(null);

  useEffect(() => {
    api.ontology().then(setFields).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!datasetId) return;
    setLoading(true);
    setSaved(null);
    api
      .getSchema(datasetId)
      .then((schema) => {
        setRows(schema);
        setDraft(
          Object.fromEntries(schema.map((c) => [c.column_name, c.mapped_field ?? UNMAPPED]))
        );
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [datasetId]);

  /* A canonical field can only be claimed once, so flag collisions before the
     request rather than letting the API 422. */
  const conflicts = useMemo(() => {
    const counts = {};
    Object.values(draft).forEach((v) => {
      if (v && v !== UNMAPPED) counts[v] = (counts[v] || 0) + 1;
    });
    return new Set(Object.keys(counts).filter((k) => counts[k] > 1));
  }, [draft]);

  const changed = useMemo(
    () =>
      rows.filter((r) => (r.mapped_field ?? UNMAPPED) !== draft[r.column_name]).map(
        (r) => r.column_name
      ),
    [rows, draft]
  );

  async function apply() {
    setSaving(true);
    setSaved(null);
    // Only send what the analyst actually touched, so untouched columns stay
    // free for the mapper to infer on the re-run.
    const overrides = Object.fromEntries(
      changed.map((col) => [col, draft[col] === UNMAPPED ? null : draft[col]])
    );
    try {
      const schema = await api.overrideSchema(datasetId, overrides);
      setRows(schema);
      setDraft(
        Object.fromEntries(schema.map((c) => [c.column_name, c.mapped_field ?? UNMAPPED]))
      );
      setSaved(`Re-analyzed with ${Object.keys(overrides).length} correction(s).`);
      setError(null);
      onReanalyzed?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  function reset() {
    setDraft(Object.fromEntries(rows.map((c) => [c.column_name, c.mapped_field ?? UNMAPPED])));
    setSaved(null);
  }

  if (!datasetId) return <EmptyState icon="↑">Upload a log file first.</EmptyState>;
  if (loading) return <Spinner label="Loading schema…" />;

  const lowConfidence = rows.filter(
    (r) => r.source !== "manual" && r.confidence > 0 && r.confidence < REVIEW_THRESHOLD
  );

  return (
    <div className="space-y-5">
      {error && <ErrorNote error={error} />}

      {lowConfidence.length > 0 && (
        <div
          className="flex items-start gap-3 rounded-2xl p-4"
          style={{
            background: `color-mix(in srgb, ${RISK_COLORS.Medium} 9%, var(--surface))`,
            boxShadow: `0 0 0 1px color-mix(in srgb, ${RISK_COLORS.Medium} 34%, transparent)`,
          }}
        >
          <span style={{ color: RISK_COLORS.Medium }}>
            <Icon name="alert" size={17} />
          </span>
          <div className="text-[13px]">
            <p className="font-semibold text-ink-primary">
              {lowConfidence.length} column{lowConfidence.length === 1 ? "" : "s"} matched
              with low confidence
            </p>
            <p className="mt-1 text-ink-secondary">
              A wrong mapping produces a wrong finding rather than no finding - for example a
              request counter read as a failed-login count will manufacture a brute-force
              alert. Correct anything below and re-run.
            </p>
          </div>
        </div>
      )}

      <Card
        title="Column mapping"
        subtitle="How each column in your file was interpreted. Change any of these and re-run the analysis."
        actions={
          <div className="flex items-center gap-2">
            {changed.length > 0 && (
              <button
                type="button"
                onClick={reset}
                disabled={saving}
                className="focusable rounded-lg px-3 py-1.5 text-[11px] text-ink-secondary transition-colors hover:text-ink-primary disabled:opacity-50"
                style={{ boxShadow: "inset 0 0 0 1px var(--border-ring)" }}
              >
                Reset
              </button>
            )}
            <button
              type="button"
              onClick={apply}
              disabled={saving || changed.length === 0 || conflicts.size > 0}
              className="focusable rounded-lg px-3 py-1.5 text-[11px] font-semibold text-white transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
              style={{ background: "var(--brand)" }}
            >
              {saving
                ? "Re-analyzing…"
                : changed.length
                  ? `Apply & re-run (${changed.length})`
                  : "Apply & re-run"}
            </button>
          </div>
        }
      >
        {conflicts.size > 0 && (
          <div className="mb-4">
            <ErrorNote
              error={`Each canonical field can only be used once. Duplicated: ${[...conflicts].join(", ")}`}
            />
          </div>
        )}
        {saved && (
          <p
            className="mb-4 rounded-xl px-3.5 py-2.5 text-[13px]"
            style={{
              color: RISK_COLORS.Low,
              background: `color-mix(in srgb, ${RISK_COLORS.Low} 10%, transparent)`,
              boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${RISK_COLORS.Low} 34%, transparent)`,
            }}
          >
            ● {saved} Detections, risk scores, and explanations were all rebuilt.
          </p>
        )}

        <div className="scroll-x -mx-1 px-1">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="text-[10px] uppercase tracking-wider text-ink-muted">
                <th className="pb-2.5 font-semibold">Your column</th>
                <th className="pb-2.5 font-semibold">Sample values</th>
                <th className="pb-2.5 font-semibold">Interpreted as</th>
                <th className="pb-2.5 font-semibold">Match</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const tone = confidenceTone(row.confidence, row.source);
                const current = draft[row.column_name] ?? UNMAPPED;
                const isChanged = (row.mapped_field ?? UNMAPPED) !== current;
                const isConflict = current !== UNMAPPED && conflicts.has(current);
                return (
                  <tr
                    key={row.column_name}
                    style={{
                      borderTop: "1px solid var(--gridline)",
                      background: isChanged ? "var(--brand-soft)" : undefined,
                    }}
                  >
                    <td className="py-2.5 align-top">
                      <div className="font-mono text-xs text-ink-primary">
                        {row.column_name}
                      </div>
                      <div className="mt-0.5 text-[10px] uppercase tracking-wide text-ink-muted">
                        {row.inferred_dtype || "unknown"}
                      </div>
                    </td>
                    <td className="max-w-[220px] py-2.5 align-top">
                      <div className="truncate font-mono text-[11px] text-ink-secondary">
                        {row.sample_values?.length ? row.sample_values.join(", ") : "-"}
                      </div>
                    </td>
                    <td className="py-2.5 align-top">
                      <select
                        value={current}
                        onChange={(e) =>
                          setDraft((d) => ({ ...d, [row.column_name]: e.target.value }))
                        }
                        className="focusable w-full max-w-[240px] rounded-lg px-2.5 py-1.5 text-xs text-ink-primary"
                        style={{
                          background: "var(--surface)",
                          boxShadow: isConflict
                            ? `inset 0 0 0 1px ${RISK_COLORS.Critical}`
                            : "inset 0 0 0 1px var(--border-ring)",
                        }}
                      >
                        <option value={UNMAPPED}>- Not mapped (kept verbatim) -</option>
                        {fields.map((f) => (
                          <option key={f.key} value={f.key}>
                            {f.display_name} ({f.key})
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2.5 align-top">
                      <div className="flex items-center gap-2">
                        <span
                          className="h-1.5 w-16 overflow-hidden rounded-full"
                          style={{ background: "var(--sunken)" }}
                        >
                          <span
                            className="block h-full rounded-full"
                            style={{
                              width: `${Math.round((row.confidence || 0) * 100)}%`,
                              background: tone.color,
                            }}
                          />
                        </span>
                        <span className="tabular text-[11px] text-ink-secondary">
                          {Math.round((row.confidence || 0) * 100)}%
                        </span>
                      </div>
                      <div className="mt-0.5 text-[10px]" style={{ color: tone.color }}>
                        {tone.label}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="text-[11px] text-ink-muted">
        Columns left unmapped are never discarded - they're preserved verbatim per row and stay
        visible in the investigation view.
      </p>
    </div>
  );
}
