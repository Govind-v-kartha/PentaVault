import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  aiAnalyze,
  aiExecutiveSummary,
  aiRemediate,
  cancelScan,
  consumeAiStream,
  deleteScan,
  fetchMitreBreakdown,
  fetchMitreReference,
  fetchMitreTactics,
  fetchOwaspReference,
  getFrontendMode,
  getScan,
  listScans,
  startScan,
  updateScan,
} from "./api/client";
import ScanForm from "./features/scan/ScanForm";
import HistoryPanel from "./features/history/HistoryPanel";
import ResultsPanel from "./features/results/ResultsPanel";
import StatusPanel from "./components/StatusPanel";

const DEFAULT_SCAN_CONFIG = {
  target: "",
  mode: "quick",
  threads: 5,
  timeout: 10,
  requestDelay: 0,
  cookie: "",
  crawlMode: "auto",
  useBrowser: false,
};

function sanitizeAiErrorMessage(error) {
  if (!error) {
    return "AI request failed.";
  }

  const detail = error?.detail || error;
  const maybeMessage =
    (typeof detail === "string" && detail) ||
    (typeof detail?.message === "string" && detail.message) ||
    (typeof error?.message === "string" && error.message) ||
    "AI request failed.";

  const lower = maybeMessage.toLowerCase();
  if (lower.includes("gemini") || lower.includes("api key") || lower.includes("key") || lower.includes("provider")) {
    return "AI service is temporarily unavailable. Please retry in a moment.";
  }
  return maybeMessage;
}

function severityTotal(summary = {}) {
  const keys = ["Critical", "High", "Medium", "Low", "Info", "None"];
  return keys.reduce((acc, key) => acc + Number(summary?.[key] ?? summary?.[key.toLowerCase()] ?? 0), 0);
}

function parseOwaspCategory(rawCategory, fallbackMap = null) {
  const raw = String(rawCategory || "").trim();
  if (!raw) {
    return { code: "Uncategorized", title: "Uncategorized" };
  }
  const parts = raw.split(" - ");
  if (parts.length > 1) {
    return { code: parts[0].trim(), title: parts.slice(1).join(" - ").trim() || parts[0].trim() };
  }
  if (fallbackMap && fallbackMap[raw]) {
    return { code: raw, title: String(fallbackMap[raw]) };
  }
  return { code: raw, title: raw };
}

function severityRank(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return 5;
  if (value === "high") return 4;
  if (value === "medium") return 3;
  if (value === "low") return 2;
  if (value === "info" || value === "none") return 1;
  return 0;
}

function flattenMitreTechniques(groups = []) {
  const flat = [];
  for (const group of groups || []) {
    for (const technique of group?.techniques || []) {
      flat.push({
        tactic: group?.tactic || "Unknown",
        techniqueId: technique?.technique_id || "-",
        name: technique?.name || "Unknown",
        confidence: technique?.confidence || "low",
        findingCount: Number(technique?.finding_count || 0),
        severityWeight: Number(technique?.severity_weight || 0),
      });
    }
  }
  return flat.sort((a, b) => {
    if (b.findingCount !== a.findingCount) {
      return b.findingCount - a.findingCount;
    }
    return b.severityWeight - a.severityWeight;
  });
}

export default function App() {
  const [frontendMode, setFrontendMode] = useState({
    selected_mode: "legacy",
    active_mode: "legacy",
    react_dist_ready: false,
    available_modes: ["legacy"],
  });
  const [scanId, setScanId] = useState("");
  const [scanData, setScanData] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("scan");
  const [statusMessage, setStatusMessage] = useState("Ready");
  const [warnings, setWarnings] = useState([]);
  const [errors, setErrors] = useState([]);
  const [aiState, setAiState] = useState({
    analysis: "",
    summary: "",
    remediation: "",
    error: "",
    streaming: false,
    remediationFindingIndex: null,
  });
  const [references, setReferences] = useState({ owasp: null, mitre: null, tactics: [] });

  const pollRef = useRef(null);

  const loadFrontendMode = useCallback(async () => {
    try {
      const payload = await getFrontendMode();
      setFrontendMode(payload);
    } catch {
      setFrontendMode((prev) => ({ ...prev, active_mode: "legacy" }));
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const rows = await listScans();
      setHistory(Array.isArray(rows) ? rows : []);
    } catch (error) {
      setStatusMessage(`History load failed: ${error.message || "unknown error"}`);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadReferences = useCallback(async () => {
    try {
      const [owasp, mitre, tactics] = await Promise.all([fetchOwaspReference(), fetchMitreReference(), fetchMitreTactics()]);
      setReferences({ owasp, mitre, tactics: Array.isArray(tactics) ? tactics : [] });
    } catch (error) {
      setStatusMessage(`Reference load warning: ${error.message || "failed"}`);
    }
  }, []);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const refreshScan = useCallback(
    async (id) => {
      if (!id) {
        return null;
      }
      setScanLoading(true);
      try {
        const payload = await getScan(id);
        setScanData(payload);
        if (payload?.status && payload.status !== "running") {
          stopPolling();
        }
        return payload;
      } catch (error) {
        setStatusMessage(`Scan refresh failed: ${error.message || "unknown error"}`);
        stopPolling();
        return null;
      } finally {
        setScanLoading(false);
      }
    },
    [stopPolling],
  );

  const startPolling = useCallback(
    (id) => {
      stopPolling();
      pollRef.current = window.setInterval(() => {
        refreshScan(id);
      }, 1500);
    },
    [refreshScan, stopPolling],
  );

  useEffect(() => {
    loadFrontendMode();
    refreshHistory();
    loadReferences();
    return () => stopPolling();
  }, [loadFrontendMode, refreshHistory, loadReferences, stopPolling]);

  async function handleStart(form) {
    setStatusMessage("Starting scan...");
    setWarnings([]);
    setErrors([]);

    const payload = {
      target: form.target,
      mode: form.mode,
      threads: Number(form.threads),
      timeout: Number(form.timeout),
      request_delay: Number(form.requestDelay),
      cookie: form.cookie?.trim() ? form.cookie.trim() : null,
      use_browser: Boolean(form.useBrowser),
      crawl_mode: form.crawlMode,
    };

    try {
      const started = await startScan(payload);
      setScanId(started.scan_id);
      setStatusMessage(`Scan started: ${started.scan_id}`);
      setActiveTab("scan");
      await refreshScan(started.scan_id);
      startPolling(started.scan_id);
      await refreshHistory();
    } catch (error) {
      const detail = error?.detail;
      const warningList = Array.isArray(detail?.warnings) ? detail.warnings : [];
      const errorList = Array.isArray(detail?.errors) ? detail.errors : [];
      setWarnings(warningList);
      setErrors(errorList.length ? errorList : [error.message || "Failed to start scan"]);
      setStatusMessage(`Start failed: ${error.message || "unknown error"}`);
    }
  }

  async function handleCancel() {
    if (!scanId) {
      return;
    }
    try {
      const payload = await cancelScan(scanId);
      if (payload?.cancelled) {
        setStatusMessage("Cancellation requested.");
      } else {
        setStatusMessage(payload?.reason || "Scan is not running.");
      }
      await refreshScan(scanId);
      await refreshHistory();
    } catch (error) {
      setStatusMessage(`Cancel failed: ${error.message || "unknown error"}`);
    }
  }

  async function handleToggleBrowser(value) {
    if (!scanId || !scanData || scanData.status !== "running") {
      return;
    }
    try {
      await updateScan(scanId, { use_browser: Boolean(value) });
      await refreshScan(scanId);
      setStatusMessage(`Browser mode set to ${value ? "enabled" : "disabled"}.`);
    } catch (error) {
      setStatusMessage(`Toggle failed: ${error.message || "unknown error"}`);
    }
  }

  async function handleOpenFromHistory(id) {
    setScanId(id);
    setActiveTab("results");
    const payload = await refreshScan(id);
    if (payload?.status === "running") {
      startPolling(id);
    }
  }

  async function handleDeleteFromHistory(id) {
    try {
      await deleteScan(id);
      if (scanId === id) {
        setScanId("");
        setScanData(null);
        stopPolling();
      }
      await refreshHistory();
    } catch (error) {
      setStatusMessage(`Delete failed: ${error.message || "unknown error"}`);
    }
  }

  async function handleAiAnalyze() {
    if (!scanId) {
      return;
    }
    setAiState((prev) => ({ ...prev, error: "", streaming: true, analysis: "" }));
    try {
      let streamText = "";
      await consumeAiStream(
        "/api/ai/analyze/stream",
        { scan_id: scanId },
        {
          onEvent: (evt) => {
            if (evt.event === "delta") {
              streamText += evt.data?.chunk || "";
              setAiState((prev) => ({ ...prev, analysis: streamText }));
            }
            if (evt.event === "final") {
              setAiState((prev) => ({ ...prev, analysis: evt.data?.analysis || streamText }));
            }
          },
          onError: (data) => {
            setAiState((prev) => ({ ...prev, error: sanitizeAiErrorMessage(data) }));
          },
        },
      );
    } catch (error) {
      if (error instanceof ApiError) {
        setAiState((prev) => ({ ...prev, error: sanitizeAiErrorMessage(error) }));
      } else {
        setAiState((prev) => ({ ...prev, error: sanitizeAiErrorMessage(error) }));
      }
    } finally {
      setAiState((prev) => ({ ...prev, streaming: false }));
    }
  }

  async function handleAiExecSummary() {
    if (!scanId) {
      return;
    }
    setAiState((prev) => ({ ...prev, error: "", summary: "" }));
    try {
      const payload = await aiExecutiveSummary(scanId);
      setAiState((prev) => ({ ...prev, summary: payload.summary || "" }));
    } catch (error) {
      setAiState((prev) => ({ ...prev, error: sanitizeAiErrorMessage(error) }));
    }
  }

  async function handleAiRemediate(index) {
    if (!scanId) {
      return;
    }
    setAiState((prev) => ({ ...prev, error: "", remediation: "", remediationFindingIndex: index }));
    try {
      const payload = await aiRemediate(scanId, index);
      setAiState((prev) => ({ ...prev, remediation: payload.remediation || "", remediationFindingIndex: index }));
    } catch (error) {
      setAiState((prev) => ({ ...prev, error: sanitizeAiErrorMessage(error), remediationFindingIndex: index }));
    }
  }

  const findingsTotal = useMemo(() => {
    if (!scanData) {
      return 0;
    }
    const fromSummary = severityTotal(scanData.summary || {});
    return fromSummary > 0 ? fromSummary : Number(scanData.findings_count || 0);
  }, [scanData]);

  const scanOwaspBreakdown = useMemo(() => {
    const findings = Array.isArray(scanData?.findings) ? scanData.findings : [];
    const groups = new Map();

    for (const finding of findings) {
      const parsed = parseOwaspCategory(finding?.owasp_category || "Uncategorized", references.owasp);
      const existing = groups.get(parsed.code) || {
        code: parsed.code,
        title: parsed.title,
        count: 0,
        maxSeverity: "Info",
      };
      existing.count += 1;
      if (severityRank(finding?.severity) > severityRank(existing.maxSeverity)) {
        existing.maxSeverity = finding?.severity || existing.maxSeverity;
      }
      groups.set(parsed.code, existing);
    }

    return Array.from(groups.values()).sort((a, b) => b.count - a.count);
  }, [scanData, references.owasp]);

  const scanMitreSummary = useMemo(() => {
    if (!references.mitreBreakdown) {
      return null;
    }
    const payload = references.mitreBreakdown;
    const matrix = payload?.matrix_coverage || {};
    const topTechniques = flattenMitreTechniques(payload?.mitre_breakdown || []).slice(0, 8);
    const attackPath = Array.isArray(payload?.attack_paths) ? payload.attack_paths : [];

    return {
      narrative: payload?.threat_narrative?.narrative || "",
      tacticsWithHits: Number(matrix?.tactics_with_hits || 0),
      totalTactics: Number(matrix?.total_tactics || 0),
      techniqueHits: Number(matrix?.total_technique_hits || 0),
      topTechniques,
      attackPath,
    };
  }, [references.mitreBreakdown]);

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[1480px] flex-col gap-4 p-4 lg:p-6">
      <header className="panel-card px-4 py-3 md:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">PentaVault Mission Dashboard</h1>
            <p className="text-sm text-slate-400">React + Vite migration shell with API compatibility and SSE AI stream support.</p>
          </div>
          <div className="rounded-md border border-slate-700 bg-slate-900/70 px-3 py-2 text-xs text-slate-300">
            Frontend mode: <strong>{frontendMode.active_mode}</strong> (selected {frontendMode.selected_mode})
          </div>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-[340px,1fr]">
        <aside className="grid gap-4">
          <nav className="panel-card p-3">
            <div className="grid grid-cols-2 gap-2 lg:grid-cols-1">
              <button
                type="button"
                className={`btn-secondary ${activeTab === "scan" ? "border-cyan-500 text-cyan-200" : ""}`}
                onClick={() => setActiveTab("scan")}
              >
                Scan
              </button>
              <button
                type="button"
                className={`btn-secondary ${activeTab === "results" ? "border-cyan-500 text-cyan-200" : ""}`}
                onClick={() => setActiveTab("results")}
              >
                Results
              </button>
              <button
                type="button"
                className={`btn-secondary ${activeTab === "history" ? "border-cyan-500 text-cyan-200" : ""}`}
                onClick={() => setActiveTab("history")}
              >
                History
              </button>
              <button
                type="button"
                className={`btn-secondary ${activeTab === "mapping" ? "border-cyan-500 text-cyan-200" : ""}`}
                onClick={() => setActiveTab("mapping")}
              >
                OWASP / MITRE
              </button>
            </div>
          </nav>

          <ScanForm
            onStart={handleStart}
            onCancel={handleCancel}
            onToggleBrowser={handleToggleBrowser}
            running={scanData?.status === "running"}
            initialValues={DEFAULT_SCAN_CONFIG}
            latestWarnings={warnings}
            latestErrors={errors}
          />

          <StatusPanel scan={scanData} />

          <section className="panel-card p-4">
            <h2 className="text-sm font-semibold text-slate-200">Session status</h2>
            <p className="mt-2 text-sm text-slate-300">{statusMessage}</p>
            <p className="mt-1 text-xs text-slate-500">Active scan: {scanId || "none"} · Findings total: {findingsTotal}</p>
          </section>
        </aside>

        <main className="grid gap-4">
          {activeTab === "results" || activeTab === "scan" ? (
            <ResultsPanel
              scan={scanData}
              loading={scanLoading}
              onAiAnalyze={handleAiAnalyze}
              onAiExecutiveSummary={handleAiExecSummary}
              onAiRemediate={handleAiRemediate}
              aiState={aiState}
            />
          ) : null}

          {activeTab === "history" ? (
            <HistoryPanel
              items={history}
              loading={historyLoading}
              activeScanId={scanId}
              onOpen={handleOpenFromHistory}
              onDelete={handleDeleteFromHistory}
              onRefresh={refreshHistory}
            />
          ) : null}

          {activeTab === "mapping" ? (
            <section className="grid gap-4">
              <article className="panel-card p-4 md:p-5">
                <h2 className="text-lg font-semibold text-slate-100">OWASP Coverage Snapshot</h2>
                <p className="mt-1 text-sm text-slate-400">Derived from current scan findings.</p>

                {!scanData?.findings?.length ? (
                  <div className="mt-3 rounded-md border border-slate-700 bg-slate-900/70 p-3 text-sm text-slate-300">
                    Run or open a completed scan to view OWASP coverage.
                  </div>
                ) : (
                  <div className="mt-3 overflow-auto rounded-md border border-slate-700">
                    <table className="min-w-full text-sm">
                      <thead className="bg-slate-900/80 text-left text-slate-300">
                        <tr>
                          <th className="px-3 py-2">Category</th>
                          <th className="px-3 py-2">Name</th>
                          <th className="px-3 py-2">Findings</th>
                          <th className="px-3 py-2">Max Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanOwaspBreakdown.map((item) => (
                          <tr key={item.code} className="border-t border-slate-800 bg-slate-950/20">
                            <td className="px-3 py-2 text-cyan-200">{item.code}</td>
                            <td className="px-3 py-2 text-slate-200">{item.title}</td>
                            <td className="px-3 py-2 text-slate-300">{item.count}</td>
                            <td className="px-3 py-2 text-slate-300">{item.maxSeverity}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </article>

              <article className="panel-card p-4 md:p-5">
                <h2 className="text-lg font-semibold text-slate-100">MITRE ATT&CK Coverage</h2>
                <p className="mt-1 text-sm text-slate-400">Attack-path and technique exposure for the active scan.</p>
                <button
                  type="button"
                  className="btn-secondary mt-3"
                  onClick={async () => {
                    if (!scanId) {
                      setStatusMessage("Open or run a scan first.");
                      return;
                    }
                    try {
                      const payload = await fetchMitreBreakdown(scanId);
                      setStatusMessage(`Loaded MITRE breakdown for ${scanId}`);
                      setReferences((prev) => ({ ...prev, mitreBreakdown: payload }));
                    } catch (error) {
                      setStatusMessage(`MITRE breakdown failed: ${error.message || "unknown error"}`);
                    }
                  }}
                >
                  Load MITRE Breakdown
                </button>

                {!scanMitreSummary ? (
                  <div className="mt-3 rounded-md border border-slate-700 bg-slate-900/70 p-3 text-sm text-slate-300">
                    No MITRE breakdown loaded yet.
                  </div>
                ) : (
                  <div className="mt-3 grid gap-3">
                    <div className="rounded-md border border-slate-700 bg-slate-900/60 p-3 text-sm text-slate-200">
                      <p>
                        Tactics hit: <strong>{scanMitreSummary.tacticsWithHits}</strong> / {scanMitreSummary.totalTactics} · Technique hits:{" "}
                        <strong>{scanMitreSummary.techniqueHits}</strong>
                      </p>
                    </div>

                    {scanMitreSummary.narrative ? (
                      <div className="rounded-md border border-slate-700 bg-slate-900/60 p-3 text-sm text-slate-200" dangerouslySetInnerHTML={{ __html: scanMitreSummary.narrative }} />
                    ) : null}

                    <div className="overflow-auto rounded-md border border-slate-700">
                      <table className="min-w-full text-sm">
                        <thead className="bg-slate-900/80 text-left text-slate-300">
                          <tr>
                            <th className="px-3 py-2">Technique</th>
                            <th className="px-3 py-2">Tactic</th>
                            <th className="px-3 py-2">Confidence</th>
                            <th className="px-3 py-2">Findings</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanMitreSummary.topTechniques.map((tech) => (
                            <tr key={`${tech.techniqueId}-${tech.tactic}`} className="border-t border-slate-800 bg-slate-950/20">
                              <td className="px-3 py-2 text-slate-200">
                                <span className="text-cyan-200">{tech.techniqueId}</span> · {tech.name}
                              </td>
                              <td className="px-3 py-2 text-slate-300">{tech.tactic}</td>
                              <td className="px-3 py-2 text-slate-300">{tech.confidence}</td>
                              <td className="px-3 py-2 text-slate-300">{tech.findingCount}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div className="rounded-md border border-slate-700 bg-slate-900/60 p-3 text-sm text-slate-200">
                      <h3 className="mb-2 text-sm font-semibold text-slate-100">Attack Path Stages</h3>
                      {scanMitreSummary.attackPath.length === 0 ? (
                        <p className="text-slate-400">No attack path stages were inferred.</p>
                      ) : (
                        <ol className="grid gap-2">
                          {scanMitreSummary.attackPath.map((stage) => (
                            <li key={stage.phase} className="rounded-md border border-slate-700 bg-slate-950/20 px-3 py-2">
                              <p className="text-slate-100">{stage.phase}</p>
                              <p className="text-xs text-slate-400">Findings in phase: {stage.finding_count}</p>
                            </li>
                          ))}
                        </ol>
                      )}
                    </div>
                  </div>
                )}
              </article>

              <article className="panel-card p-4 md:p-5">
                <h2 className="text-lg font-semibold text-slate-100">Reference Datasets</h2>
                <p className="mt-1 text-sm text-slate-400">Static OWASP and MITRE sources returned by backend APIs.</p>
                <pre className="mt-3 max-h-[260px] overflow-auto rounded-md border border-slate-700 bg-slate-900/70 p-3 text-xs text-slate-200">
                  {JSON.stringify(
                    {
                      owaspCategories: references.owasp ? Object.keys(references.owasp).length : 0,
                      mitreTechniques: references.mitre ? Object.keys(references.mitre).length : 0,
                      tactics: references.tactics,
                    },
                    null,
                    2,
                  )}
                </pre>
              </article>
            </section>
          ) : null}
        </main>
      </div>
    </div>
  );
}
