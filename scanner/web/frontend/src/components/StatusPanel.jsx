export default function StatusPanel({ scan }) {
  if (!scan) {
    return (
      <section className="panel-card p-4 md:p-5">
        <h2 className="text-lg font-semibold text-slate-100">Runtime Status</h2>
        <p className="mt-2 text-sm text-slate-400">No active scan context.</p>
      </section>
    );
  }

  const runtime = scan.runtime_config ?? {};
  const execution = scan.execution_metadata ?? {};

  return (
    <section className="panel-card p-4 md:p-5">
      <h2 className="text-lg font-semibold text-slate-100">Runtime Status</h2>
      <p className="mt-1 text-sm text-slate-400">Execution metadata from /api/scan/{'{scan_id}'}.</p>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3">
          <h3 className="text-sm font-semibold text-slate-200">Runtime Config</h3>
          <dl className="mt-2 grid grid-cols-2 gap-y-1 text-sm text-slate-300">
            <dt>Mode</dt><dd>{runtime.mode ?? "-"}</dd>
            <dt>Threads</dt><dd>{runtime.threads ?? "-"}</dd>
            <dt>Timeout</dt><dd>{runtime.timeout_seconds ?? "-"}s</dd>
            <dt>Delay</dt><dd>{runtime.request_delay_seconds ?? "-"}s</dd>
            <dt>Browser</dt><dd>{String(runtime.use_browser ?? false)}</dd>
            <dt>Crawl</dt><dd>{runtime.crawl_mode ?? "-"}</dd>
          </dl>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3">
          <h3 className="text-sm font-semibold text-slate-200">Execution Metadata</h3>
          <dl className="mt-2 grid grid-cols-2 gap-y-1 text-sm text-slate-300">
            <dt>HTTP Workers</dt><dd>{execution.http_module_workers ?? "-"}</dd>
            <dt>Resolved Crawl</dt><dd>{execution.resolved_crawl_mode ?? "-"}</dd>
            <dt>HTTP Modules</dt><dd>{execution.http_module_count ?? "-"}</dd>
            <dt>Browser Modules</dt><dd>{execution.browser_module_count ?? "-"}</dd>
            <dt>Browser Exec</dt><dd>{execution.browser_module_execution ?? "-"}</dd>
            <dt>Browser Timeout</dt><dd>{execution.browser_module_timeout_seconds ?? 0}s</dd>
          </dl>
        </div>
      </div>
    </section>
  );
}
