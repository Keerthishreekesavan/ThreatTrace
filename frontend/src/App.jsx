import { useCallback, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";

import Analytics from "./pages/Analytics";
import Investigation from "./pages/Investigation";
import Overview from "./pages/Overview";
import Schema from "./pages/Schema";
import Timeline from "./pages/Timeline";
import Upload from "./pages/Upload";
import { api } from "./api";
import Icon from "./components/Icon";
import { ErrorNote } from "./components/ui";

const NAV = [
  { to: "/upload", label: "Upload", icon: "upload", hint: "Ingest a log" },
  { to: "/schema", label: "Schema", icon: "layers", hint: "Review & correct column mapping" },
  { to: "/overview", label: "Overview", icon: "grid", hint: "Posture at a glance" },
  { to: "/timeline", label: "Timeline", icon: "activity", hint: "Correlate over time" },
  { to: "/investigation", label: "Investigation", icon: "target", hint: "Drill into an IP" },
  { to: "/analytics", label: "Analytics", icon: "chart", hint: "Aggregate views" },
];

const PAGE_TITLES = {
  "/upload": ["Upload", "Drop in any CSV or JSON security log"],
  "/schema": ["Schema mapping", "Review how your columns were interpreted - and correct them"],
  "/overview": ["Overview", "Current threat posture for the active dataset"],
  "/timeline": ["Timeline", "Event volume and detections over time"],
  "/investigation": ["Investigation", "Evidence and progression for a single source IP"],
  "/analytics": ["Analytics", "Top offenders, categories, and geography"],
};

export default function App() {
  const [datasets, setDatasets] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [theme, setTheme] = useState(
    () => document.documentElement.getAttribute("data-theme") || "dark"
  );
  const [error, setError] = useState(null);
  const [navOpen, setNavOpen] = useState(false);

  const refreshDatasets = useCallback(async (selectId) => {
    try {
      const list = await api.listDatasets();
      setDatasets(list);
      setActiveId((current) => selectId ?? current ?? list[0]?.id ?? null);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    refreshDatasets();
  }, [refreshDatasets]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const activeDataset = datasets.find((d) => d.id === activeId) || null;
  // useLocation (not window.location) so the heading tracks client-side nav.
  const { pathname } = useLocation();
  const [pageTitle, pageSub] = PAGE_TITLES[pathname] || ["ThreatTrace", ""];

  return (
    <div className="flex min-h-screen">
      {/* ── Sidebar ────────────────────────────────────────────────────────── */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-[228px] flex-col p-4 transition-transform lg:static lg:translate-x-0 ${
          navOpen ? "translate-x-0" : "-translate-x-full"
        }`}
        style={{ background: "var(--surface)", boxShadow: "1px 0 0 var(--border-ring)" }}
      >
        <div className="flex items-center gap-2.5 px-2 py-2">
          <span
            aria-hidden="true"
            className="grid h-8 w-8 place-items-center rounded-xl text-sm font-bold text-white"
            style={{
              background: "linear-gradient(140deg, var(--brand), var(--series-1))",
              boxShadow: "0 4px 14px var(--glow)",
            }}
          >
            T
          </span>
          <div>
            <div className="text-sm font-semibold leading-tight tracking-tight">ThreatTrace</div>
            <div className="text-[10px] uppercase tracking-wider text-ink-muted">
              Threat analytics
            </div>
          </div>
        </div>

        <nav className="mt-5 flex flex-col gap-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setNavOpen(false)}
              title={item.hint}
              className="focusable group flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] transition-colors"
              style={({ isActive }) =>
                isActive
                  ? {
                      background: "var(--brand-soft)",
                      color: "var(--text-primary)",
                      fontWeight: 600,
                      boxShadow: "inset 0 0 0 1px var(--brand-ring)",
                    }
                  : { color: "var(--text-secondary)" }
              }
            >
              {({ isActive }) => (
                <>
                  <span
                    aria-hidden="true"
                    className="grid h-7 w-7 shrink-0 place-items-center rounded-lg transition-colors"
                    style={{
                      background: isActive ? "var(--brand)" : "var(--sunken)",
                      color: isActive ? "#fff" : "var(--text-muted)",
                    }}
                  >
                    <Icon name={item.icon} size={15} />
                  </span>
                  {item.label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-2 pt-4">
          <a
            href="/landing/index.html"
            className="focusable rounded-xl px-3 py-2 text-[12px] text-ink-secondary transition-colors hover:text-ink-primary"
            style={{ boxShadow: "inset 0 0 0 1px var(--border-ring)" }}
          >
            About this project ↗
          </a>
          <button
            type="button"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            className="focusable rounded-xl px-3 py-2 text-left text-[12px] text-ink-secondary transition-colors hover:text-ink-primary"
            style={{ boxShadow: "inset 0 0 0 1px var(--border-ring)" }}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            {theme === "dark" ? "☀ Light mode" : "☾ Dark mode"}
          </button>
        </div>
      </aside>

      {navOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
          className="fixed inset-0 z-20 bg-black/50 lg:hidden"
        />
      )}

      {/* ── Main ───────────────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="sticky top-0 z-10 flex flex-wrap items-center gap-x-4 gap-y-3 px-6 py-4"
          style={{
            background: "color-mix(in srgb, var(--plane) 86%, transparent)",
            backdropFilter: "blur(10px)",
            boxShadow: "0 1px 0 var(--border-ring)",
          }}
        >
          <button
            type="button"
            onClick={() => setNavOpen(true)}
            className="focusable rounded-lg px-2 py-1 text-sm lg:hidden"
            style={{ boxShadow: "inset 0 0 0 1px var(--border-ring)" }}
            aria-label="Open navigation"
          >
            ☰
          </button>

          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold tracking-tight">{pageTitle}</h1>
            <p className="truncate text-xs text-ink-secondary">
              {pageSub}
              {/* Plain text, not a control: the header no longer offers a dataset
                  picker (switching happens on the Upload page), but which dataset
                  is being analyzed is still essential context on every view. */}
              {activeDataset && pathname !== "/upload" && (
                <span className="text-ink-muted">
                  {pageSub ? " · " : ""}
                  <span className="font-mono">{activeDataset.filename}</span>
                </span>
              )}
            </p>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-6 py-6">
          {error && (
            <div className="mb-4">
              <ErrorNote error={`${error} - is the API running on port 8000?`} />
            </div>
          )}

          <Routes>
            <Route path="/" element={<Navigate to="/upload" replace />} />
            <Route
              path="/upload"
              element={
                <Upload
                  datasets={datasets}
                  activeId={activeId}
                  onUploaded={(d) => refreshDatasets(d.id)}
                  onSelect={setActiveId}
                />
              }
            />
            <Route
              path="/schema"
              element={<Schema datasetId={activeId} onReanalyzed={() => refreshDatasets(activeId)} />}
            />
            <Route path="/overview" element={<Overview datasetId={activeId} theme={theme} />} />
            <Route path="/timeline" element={<Timeline datasetId={activeId} theme={theme} />} />
            <Route
              path="/investigation"
              element={<Investigation datasetId={activeId} theme={theme} />}
            />
            <Route path="/analytics" element={<Analytics datasetId={activeId} theme={theme} />} />
          </Routes>

          {activeDataset && (
            <p className="mt-8 text-[11px] text-ink-muted">
              {activeDataset.filename} · {activeDataset.row_count} events
              {activeDataset.unmapped_columns?.length
                ? ` · ${activeDataset.unmapped_columns.length} unmapped column(s) preserved`
                : ""}
            </p>
          )}
        </main>
      </div>
    </div>
  );
}
