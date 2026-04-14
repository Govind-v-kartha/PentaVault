export default function HistoryPanel({ items, loading, activeScanId, onOpen, onDelete, onRefresh }) {
  return (
    <section className="panel-card p-4 md:p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Scan History</h2>
          <p className="text-sm text-slate-400">Recent missions from /api/scans.</p>
        </div>
        <button type="button" className="btn-secondary" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-sm text-slate-300">Loading history…</div>
      ) : null}

      {!loading && items.length === 0 ? (
        <div className="rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-sm text-slate-300">No historical scans yet.</div>
      ) : null}

      <div className="grid gap-2">
        {items.map((scan) => {
          const isActive = scan.scan_id === activeScanId;
          return (
            <article
              key={scan.scan_id}
              className={`rounded-lg border p-3 ${
                isActive ? "border-cyan-500/80 bg-cyan-900/20" : "border-slate-700 bg-slate-900/70"
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="font-medium text-slate-100">{scan.target}</p>
                  <p className="text-xs uppercase tracking-wide text-slate-400">
                    {scan.mode} · {scan.status} · findings {scan.findings_count ?? 0}
                  </p>
                  <p className="text-xs text-slate-500">{scan.scan_id}</p>
                </div>
                <div className="flex gap-2">
                  <button type="button" className="btn-secondary" onClick={() => onOpen?.(scan.scan_id)}>
                    Open
                  </button>
                  <button type="button" className="btn-secondary" onClick={() => onDelete?.(scan.scan_id)}>
                    Delete
                  </button>
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
