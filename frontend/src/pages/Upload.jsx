import { useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api";
import Icon from "../components/Icon";
import { Card, EmptyState, ErrorNote, Spinner } from "../components/ui";
import { RISK_COLORS } from "../theme";

const ACCEPT = ".csv,.json";
const REVIEW_THRESHOLD = 0.6;

/* Confidence is the softmax-calibrated mapping confidence from the backend
   schema mapper. Shown as a number *and* a proportional bar, so the value never
   depends on reading a colour. */
function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100);
  const color = pct / 100 >= REVIEW_THRESHOLD ? RISK_COLORS.Low : RISK_COLORS.Medium;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full" style={{ background: "var(--sunken)" }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="tabular w-8 text-right text-[11px] text-ink-secondary">{pct}%</span>
    </div>
  );
}

function StepHint({ n, title, body }) {
  return (
    <div className="flex gap-3">
      <span
        aria-hidden="true"
        className="grid h-6 w-6 shrink-0 place-items-center rounded-full text-[11px] font-semibold"
        style={{
          background: "var(--brand-soft)",
          color: "var(--brand)",
          boxShadow: "inset 0 0 0 1px var(--brand-ring)",
        }}
      >
        {n}
      </span>
      <div>
        <div className="text-[13px] font-medium text-ink-primary">{title}</div>
        <p className="mt-0.5 text-[11px] leading-snug text-ink-secondary">{body}</p>
      </div>
    </div>
  );
}

export default function Upload({ datasets, activeId, onUploaded, onSelect }) {
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [schema, setSchema] = useState([]);

  async function handleFile(file) {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setSchema([]);
    try {
      const dataset = await api.upload(file);
      const mapping = await api.getSchema(dataset.id);
      setResult(dataset);
      setSchema(mapping);
      onUploaded(dataset);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
      setDragging(false);
    }
  }

  const mapped = schema.filter((c) => c.mapped_field);
  const unmapped = schema.filter((c) => !c.mapped_field);
  const needsReview = mapped.filter((c) => c.confidence < REVIEW_THRESHOLD);

  return (
    <div className="space-y-5">
      {/* ── Dropzone ─────────────────────────────────────────────────────── */}
      <section className="panel brand-wash overflow-hidden">
        <div className="grid gap-0 lg:grid-cols-[1fr_300px]">
          <div className="p-6">
            <label
              className="focusable relative flex cursor-pointer flex-col items-center justify-center rounded-2xl px-6 py-14 text-center transition-all"
              style={{
                border: `2px dashed ${dragging ? "var(--brand)" : "var(--baseline)"}`,
                background: dragging ? "var(--brand-soft)" : "transparent",
              }}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                handleFile(e.dataTransfer.files?.[0]);
              }}
            >
              <span
                aria-hidden="true"
                className="grid h-14 w-14 place-items-center rounded-2xl transition-transform"
                style={{
                  background: "linear-gradient(140deg, var(--brand), var(--series-1))",
                  color: "#fff",
                  boxShadow: "0 8px 24px var(--glow)",
                  transform: dragging ? "scale(1.06)" : "none",
                }}
              >
                <Icon name="upload" size={24} />
              </span>

              {busy ? (
                <Spinner label="Analyzing schema and detecting threats…" />
              ) : (
                <>
                  <span className="mt-4 text-base font-semibold text-ink-primary">
                    {dragging ? "Drop to analyze" : "Drop a log file here"}
                  </span>
                  <span className="mt-1 text-[13px] text-ink-secondary">
                    or <span style={{ color: "var(--brand)" }}>click to browse</span> · CSV or JSON
                  </span>
                </>
              )}

              <input
                type="file"
                accept={ACCEPT}
                className="sr-only"
                disabled={busy}
                onChange={(e) => handleFile(e.target.files?.[0])}
              />
            </label>

            <div className="mt-4">
              <ErrorNote error={error} />
            </div>
          </div>

          {/* What actually happens, so the page explains itself. */}
          <div
            className="flex flex-col gap-4 p-6 lg:border-l"
            style={{ borderColor: "var(--gridline)" }}
          >
            <h2 className="text-[13px] font-semibold tracking-tight text-ink-primary">
              What happens next
            </h2>
            <StepHint
              n="1"
              title="Columns are inferred"
              body="Name, type, and actual values are matched against a 13-concept threat ontology. Nothing is hardcoded."
            />
            <StepHint
              n="2"
              title="Threats are detected"
              body="Four explainable rules plus an Isolation Forest, grouped per source IP over sliding windows."
            />
            <StepHint
              n="3"
              title="Findings are explained"
              body="A 0-100 risk score with the evidence behind it. Correct any mapping on the Schema page and re-run."
            />
          </div>
        </div>
      </section>

      {/* ── Result of the upload just performed ──────────────────────────── */}
      {result && (
        <Card
          title="Semantic schema interpretation"
          subtitle={`${result.filename} · ${result.row_count} events · ${mapped.length} of ${schema.length} columns mapped`}
          actions={
            <Link
              to="/schema"
              className="focusable rounded-lg px-3 py-1.5 text-[11px] font-semibold text-white"
              style={{ background: "var(--brand)" }}
            >
              Review &amp; correct →
            </Link>
          }
        >
          {needsReview.length > 0 && (
            <p
              className="mb-4 rounded-xl px-3.5 py-2.5 text-[12px]"
              style={{
                color: RISK_COLORS.Medium,
                background: `color-mix(in srgb, ${RISK_COLORS.Medium} 10%, transparent)`,
                boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${RISK_COLORS.Medium} 34%, transparent)`,
              }}
            >
              ▲ {needsReview.length} column{needsReview.length === 1 ? "" : "s"} matched below 60%
              confidence. A wrong mapping produces a wrong finding, so it's worth a look on the
              Schema page.
            </p>
          )}

          <div className="max-h-[320px] overflow-y-auto pr-1">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0" style={{ background: "var(--surface)" }}>
                <tr className="text-[10px] uppercase tracking-wider text-ink-muted">
                  <th className="pb-2 font-semibold">Original column</th>
                  <th className="pb-2 font-semibold">Interpreted as</th>
                  <th className="pb-2 font-semibold">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {mapped.map((col) => (
                  <tr key={col.column_name} style={{ borderTop: "1px solid var(--gridline)" }}>
                    <td className="py-2 font-mono text-xs text-ink-primary">{col.column_name}</td>
                    <td className="py-2 text-[13px] text-ink-secondary">{col.mapped_field}</td>
                    <td className="py-2">
                      <ConfidenceBar value={col.confidence} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {unmapped.length > 0 && (
            <p className="mt-4 text-[11px] text-ink-secondary">
              <span className="font-semibold text-ink-primary">
                {unmapped.length} column{unmapped.length === 1 ? "" : "s"} left unmapped
              </span>{" "}
              ({unmapped.map((c) => c.column_name).join(", ")}) - below the confidence threshold, so
              they were preserved verbatim rather than forced into a canonical field.
            </p>
          )}
        </Card>
      )}

      {/* ── Previously analyzed, scrollable ──────────────────────────────── */}
      <Card
        title="Previously analyzed"
        subtitle={
          datasets.length
            ? `${datasets.length} dataset${datasets.length === 1 ? "" : "s"} · click one to make it active`
            : undefined
        }
      >
        {datasets.length === 0 ? (
          <EmptyState icon="▦">Nothing analyzed yet. Upload a log above to begin.</EmptyState>
        ) : (
          /* Capped height with its own scroll, so a long history can't push the
             rest of the page away. The fade below is a pointer-events-none hint
             that there's more to scroll; the clipped row already implies it, so
             the fade is reinforcement rather than the only cue. */
          <div className="relative">
            {datasets.length > 4 && (
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-0 bottom-0 z-10 h-10 rounded-b-xl"
                style={{
                  background: "linear-gradient(to top, var(--surface), transparent)",
                }}
              />
            )}
            <ul className="max-h-[300px] space-y-1 overflow-y-auto pr-1">
            {datasets.map((d) => {
              const active = d.id === activeId;
              return (
                <li key={d.id}>
                  <button
                    type="button"
                    onClick={() => onSelect?.(d.id)}
                    aria-current={active ? "true" : undefined}
                    className="focusable flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors"
                    style={
                      active
                        ? {
                            background: "var(--brand-soft)",
                            boxShadow: "inset 0 0 0 1px var(--brand-ring)",
                          }
                        : undefined
                    }
                  >
                    <span
                      aria-hidden="true"
                      className="grid h-7 w-7 shrink-0 place-items-center rounded-lg"
                      style={{
                        background: active ? "var(--brand)" : "var(--sunken)",
                        color: active ? "#fff" : "var(--text-muted)",
                      }}
                    >
                      <Icon name="layers" size={13} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] text-ink-primary">
                        {d.filename}
                      </span>
                      <span className="block text-[10px] text-ink-muted">
                        {new Date(d.uploaded_at).toLocaleString(undefined, {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                        {d.unmapped_columns?.length
                          ? ` · ${d.unmapped_columns.length} unmapped`
                          : ""}
                      </span>
                    </span>
                    <span className="tabular shrink-0 text-[11px] text-ink-secondary">
                      {d.row_count.toLocaleString()} events
                    </span>
                    {active && (
                      <span
                        className="shrink-0 text-[10px] font-semibold uppercase tracking-wider"
                        style={{ color: "var(--brand)" }}
                      >
                        Active
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}
