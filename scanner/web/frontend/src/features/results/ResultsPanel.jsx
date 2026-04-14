import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
  None: "#64748b",
  Info: "#64748b",
};

function classifySeverity(summary = {}) {
  const keys = ["Critical", "High", "Medium", "Low", "Info"];
  return keys
    .map((key) => ({
      name: key,
      value: Number(summary?.[key] ?? summary?.[key.toLowerCase()] ?? 0),
      color: SEVERITY_COLORS[key] ?? "#64748b",
    }))
    .filter((entry) => entry.value > 0);
}

function moduleCounts(findings = []) {
  const counts = new Map();
  for (const finding of findings) {
    const moduleName = finding?.module || finding?.type || finding?.title || "Unknown";
    counts.set(moduleName, (counts.get(moduleName) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10);
}

function normalizeFinding(finding = {}) {
  return {
    severity: finding.severity || "N/A",
    label: finding.title || finding.type || finding.module || finding.id || "Unknown",
    location: finding.affected_url || finding.path || finding.url || "-",
    detail: finding.detail || finding.remediation || "-",
  };
}

function severityBadgeClass(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return "bg-rose-900/40 text-rose-200 border-rose-700/60";
  if (value === "high") return "bg-orange-900/40 text-orange-200 border-orange-700/60";
  if (value === "medium") return "bg-amber-900/40 text-amber-200 border-amber-700/60";
  if (value === "low") return "bg-emerald-900/40 text-emerald-200 border-emerald-700/60";
  return "bg-slate-900/60 text-slate-300 border-slate-700";
}

export default function ResultsPanel({ scan, loading, onAiAnalyze, onAiExecutiveSummary, onAiRemediate, aiState }) {
  const findings = scan?.findings ?? [];
  const summary = scan?.summary ?? {};
  const [filterText, setFilterText] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");

  const severityData = useMemo(() => classifySeverity(summary), [summary]);
  const moduleData = useMemo(() => moduleCounts(findings), [findings]);

  const filteredFindings = useMemo(() => {
    return findings
      .map((finding, index) => ({ finding, index, normalized: normalizeFinding(finding) }))
      .filter(({ normalized }) => {
        const severityOk = !filterSeverity || String(normalized.severity).toLowerCase() === filterSeverity.toLowerCase();
        const hay = `${normalized.label} ${normalized.location} ${normalized.detail}`.toLowerCase();
        const textOk = !filterText || hay.includes(filterText.toLowerCase());
        return severityOk && textOk;
      });
  }, [findings, filterSeverity, filterText]);

  if (!scan) {
    return (
      <section className="panel-card p-4 md:p-5">
        <h2 className="text-lg font-semibold text-slate-100">Results</h2>
        <p className="mt-2 text-sm text-slate-400">Run or open a scan to view findings, charts, and AI output.</p>
      </section>
    );
  }

  return (
    <section className="grid gap-4">
      <article className="panel-card p-4 md:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Mission Results</h2>
            <p className="text-sm text-slate-400">{scan.target} · {scan.mode} · {scan.status}</p>
          </div>
          <div className="text-sm text-slate-300">
            <p>Progress: {scan.progress ?? 0}%</p>
            <p>Findings: {scan.findings_count ?? findings.length}</p>
            <p>Elapsed: {scan.elapsed ?? 0}s</p>
          </div>
        </div>

        {loading ? <p className="mt-3 text-sm text-slate-400">Refreshing scan status…</p> : null}

        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3">
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Severity Distribution</h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" outerRadius={84} innerRadius={42}>
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3">
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Top Modules by Findings</h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={moduleData} margin={{ left: 8, right: 8, top: 8, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94a3b8" interval={0} angle={-20} textAnchor="end" height={56} />
                  <YAxis stroke="#94a3b8" />
                  <Tooltip />
                  <Bar dataKey="value" fill="#22d3ee" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </article>

      <article className="panel-card p-4 md:p-5">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <button type="button" className="btn-primary" onClick={onAiAnalyze} disabled={Boolean(aiState?.streaming)}>
            {aiState?.streaming ? "Analyzing…" : "AI Analyze"}
          </button>
          <button type="button" className="btn-secondary" onClick={onAiExecutiveSummary} disabled={Boolean(aiState?.streaming)}>
            AI Executive Summary
          </button>
        </div>

        {!aiState?.analysis && !aiState?.summary && !aiState?.error ? (
          <div className="rounded-md border border-slate-700 bg-slate-900/70 p-3 text-sm text-slate-300">
            Run AI actions to generate analysis and executive summary for this scan.
          </div>
        ) : null}

        {aiState?.analysis ? (
          <div className="mb-3 rounded-md border border-cyan-700/40 bg-cyan-950/20 p-3">
            <h4 className="mb-1 text-sm font-semibold text-cyan-200">Analysis</h4>
            <div className="text-sm text-slate-200" dangerouslySetInnerHTML={{ __html: aiState.analysis }} />
          </div>
        ) : null}

        {aiState?.summary ? (
          <div className="rounded-md border border-indigo-700/40 bg-indigo-950/20 p-3">
            <h4 className="mb-1 text-sm font-semibold text-indigo-200">Executive Summary</h4>
            <div className="text-sm text-slate-200" dangerouslySetInnerHTML={{ __html: aiState.summary }} />
          </div>
        ) : null}

        {aiState?.error ? (
          <div className="mt-3 rounded-md border border-rose-700/50 bg-rose-950/30 p-3 text-sm text-rose-200">{aiState.error}</div>
        ) : null}
      </article>

      <article className="panel-card p-4 md:p-5">
        <div className="mb-3 flex flex-wrap gap-2">
          <input
            className="input md:max-w-xs"
            placeholder="Filter findings"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
          />
          <select className="input md:max-w-[180px]" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        <div className="overflow-auto rounded-lg border border-slate-700">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900/80 text-left text-slate-300">
              <tr>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Path</th>
                <th className="px-3 py-2">Detail</th>
                <th className="px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map(({ index, normalized }) => (
                <tr key={`${normalized.label}-${index}`} className="border-t border-slate-800 bg-slate-950/20 align-top">
                  <td className="px-3 py-2">
                    <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-semibold ${severityBadgeClass(normalized.severity)}`}>
                      {normalized.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-100">{normalized.label}</td>
                  <td className="px-3 py-2 text-slate-300">{normalized.location}</td>
                  <td className="px-3 py-2 text-slate-300">{normalized.detail}</td>
                  <td className="px-3 py-2">
                    <button type="button" className="btn-secondary" onClick={() => onAiRemediate?.(index)}>
                      {aiState?.remediationFindingIndex === index ? "AI Remediate (active)" : "AI Remediate"}
                    </button>
                  </td>
                </tr>
              ))}
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-slate-400">
                    No findings match the current filters.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        {aiState?.remediation ? (
          <div className="mt-3 rounded-md border border-emerald-700/40 bg-emerald-950/20 p-3">
            <h4 className="mb-1 text-sm font-semibold text-emerald-200">Remediation Guidance</h4>
            <div className="text-sm text-slate-200" dangerouslySetInnerHTML={{ __html: aiState.remediation }} />
          </div>
        ) : null}
      </article>
    </section>
  );
}
