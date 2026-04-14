import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { listScans, deleteScan } from '../api/client';
import './HistoryPage.css';

export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    listScans()
      .then(data => {
        const sorted = (Array.isArray(data) ? data : [])
          .sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''));
        setScans(sorted);
      })
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm('Delete this scan permanently?')) return;
    try {
      await deleteScan(id);
      setScans(prev => prev.filter(s => s.scan_id !== id));
    } catch (err) { alert('Failed to delete: ' + err.message); }
  };

  const formatDate = (iso) => {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  };

  const formatDuration = (s) => {
    if (!s) return '-';
    const sec = Math.round(Number(s));
    const m = Math.floor(sec / 60);
    return m > 0 ? `${m}m ${sec % 60}s` : `${sec}s`;
  };

  return (
    <div className="history-page">
      <header className="history-header">
        <div>
          <h1>Scan History</h1>
          <p className="text-fog text-sm">All previous vulnerability assessment missions.</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>↻ Refresh</button>
      </header>

      {loading ? (
        <div className="glass-card">
          <div className="shimmer" style={{ height: 200, borderRadius: 'var(--radius-sm)' }} />
        </div>
      ) : scans.length === 0 ? (
        <div className="glass-card">
          <div className="empty-state">
            <span className="empty-icon">📡</span>
            <p>No scan history found.</p>
            <Link to="/scan" className="btn btn-primary">Launch First Scan</Link>
          </div>
        </div>
      ) : (
        <div className="history-list">
          {scans.map(scan => {
            const statusClass = scan.status === 'completed' ? 'status-ok' :
                                scan.status === 'failed' ? 'status-fail' :
                                scan.status === 'running' ? 'status-run' : 'status-warn';
            const linkTo = scan.status === 'running'
              ? `/scan/${scan.scan_id}/live`
              : `/scan/${scan.scan_id}/results`;

            return (
              <Link key={scan.scan_id} to={linkTo} className="history-card glass-card">
                <div className="hc-top">
                  <div className={`scan-status-dot ${statusClass}`} />
                  <span className="hc-target truncate">{scan.target || 'Unknown'}</span>
                  <span className={`hc-status ${statusClass}`}>{scan.status}</span>
                </div>
                <div className="hc-meta">
                  <span className="mono text-xs">{(scan.mode || 'quick').toUpperCase()}</span>
                  <span className="text-xs text-fog">{formatDate(scan.started_at)}</span>
                  <span className="mono text-xs">{formatDuration(scan.elapsed)}</span>
                  <span className="mono text-xs">{scan.findings_count || 0} findings</span>
                </div>

                {/* Severity quick view */}
                {scan.severity_counts && (
                  <div className="hc-sev-bar">
                    {['Critical','High','Medium','Low'].map(sev => {
                      const count = scan.severity_counts?.[sev] || 0;
                      if (!count) return null;
                      return (
                        <span key={sev} className={`sev-mini sev-${sev.toLowerCase()}`}>
                          {count} {sev[0]}
                        </span>
                      );
                    })}
                  </div>
                )}

                <button className="hc-delete" onClick={(e) => handleDelete(scan.scan_id, e)} title="Delete scan">
                  🗑
                </button>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
