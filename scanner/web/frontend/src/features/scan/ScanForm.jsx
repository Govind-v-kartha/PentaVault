import { useMemo, useState } from "react";

const MODE_OPTIONS = [
  { value: "quick", label: "Quick" },
  { value: "full", label: "Full" },
  { value: "web-only", label: "Web Only" },
  { value: "network-only", label: "Network Only" },
];

const CRAWL_OPTIONS = [
  { value: "auto", label: "Auto" },
  { value: "httpx", label: "HTTP" },
  { value: "selenium", label: "Selenium" },
  { value: "hybrid", label: "Hybrid" },
];

export default function ScanForm({
  onStart,
  onCancel,
  onToggleBrowser,
  running,
  initialValues,
  latestWarnings = [],
  latestErrors = [],
}) {
  const [form, setForm] = useState(
    initialValues ?? {
      target: "",
      mode: "quick",
      threads: 5,
      timeout: 10,
      requestDelay: 0,
      cookie: "",
      crawlMode: "auto",
      useBrowser: false,
    },
  );

  const canSubmit = useMemo(() => {
    if (running) {
      return false;
    }
    return Boolean((form.target || "").trim());
  }, [form.target, running]);

  function updateField(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    onStart?.(form);
  }

  function handleBrowserToggle(event) {
    const checked = event.target.checked;
    updateField("useBrowser", checked);
    onToggleBrowser?.(checked);
  }

  return (
    <form className="panel-card p-4 md:p-5" onSubmit={handleSubmit}>
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-slate-100">Scan Launch</h2>
        <p className="mt-1 text-sm text-slate-400">Start or tune a mission using the existing PentaVault API contract.</p>
      </div>

      <div className="grid gap-4">
        <label className="grid gap-1">
          <span className="text-sm text-slate-300">Target URL / IP</span>
          <input
            className="input"
            value={form.target}
            onChange={(e) => updateField("target", e.target.value)}
            placeholder="https://example.com"
            required
          />
        </label>

        <div className="grid gap-1">
          <span className="text-sm text-slate-300">Mode</span>
          <select className="input" value={form.mode} onChange={(e) => updateField("mode", e.target.value)}>
            {MODE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <label className="grid gap-1">
            <span className="text-sm text-slate-300">Threads</span>
            <input
              className="input"
              type="number"
              min={1}
              max={10}
              value={form.threads}
              onChange={(e) => updateField("threads", Number(e.target.value || 1))}
            />
          </label>

          <label className="grid gap-1">
            <span className="text-sm text-slate-300">Timeout (s)</span>
            <input
              className="input"
              type="number"
              min={1}
              max={60}
              value={form.timeout}
              onChange={(e) => updateField("timeout", Number(e.target.value || 1))}
            />
          </label>

          <label className="grid gap-1">
            <span className="text-sm text-slate-300">Request Delay (s)</span>
            <input
              className="input"
              type="number"
              min={0}
              max={2}
              step={0.1}
              value={form.requestDelay}
              onChange={(e) => updateField("requestDelay", Number(e.target.value || 0))}
            />
          </label>
        </div>

        <label className="grid gap-1">
          <span className="text-sm text-slate-300">Cookie (optional)</span>
          <input
            className="input"
            value={form.cookie}
            onChange={(e) => updateField("cookie", e.target.value)}
            placeholder="session=abc123"
          />
        </label>

        <div className="grid gap-1">
          <span className="text-sm text-slate-300">Crawl mode</span>
          <select className="input" value={form.crawlMode} onChange={(e) => updateField("crawlMode", e.target.value)}>
            {CRAWL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <label className="flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
          <input type="checkbox" checked={form.useBrowser} onChange={handleBrowserToggle} />
          <span className="text-sm text-slate-200">Use Selenium Browser Engine</span>
        </label>
      </div>

      {(latestWarnings.length > 0 || latestErrors.length > 0) && (
        <div className="mt-4 grid gap-2 text-sm">
          {latestWarnings.length > 0 && (
            <div className="rounded-md border border-amber-700/60 bg-amber-950/40 px-3 py-2 text-amber-200">
              <strong>Warnings:</strong>
              <ul className="ml-4 list-disc">
                {latestWarnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
          {latestErrors.length > 0 && (
            <div className="rounded-md border border-rose-700/60 bg-rose-950/40 px-3 py-2 text-rose-200">
              <strong>Errors:</strong>
              <ul className="ml-4 list-disc">
                {latestErrors.map((error) => (
                  <li key={error}>{error}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="mt-5 flex flex-wrap gap-2">
        <button type="submit" className="btn-primary" disabled={!canSubmit}>
          {running ? "Running..." : "Start Scan"}
        </button>
        <button type="button" className="btn-secondary" disabled={!running} onClick={() => onCancel?.()}>
          Cancel Scan
        </button>
      </div>
    </form>
  );
}
