import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { listScans } from '../api/client';
import './DashboardPage.css';

export default function DashboardPage() {
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then(data => {
        const sorted = (Array.isArray(data) ? data : [])
          .sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''))
          .slice(0, 5);
        setRecentScans(sorted);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const totalFindings = recentScans.reduce((s, sc) => s + (sc.findings_count || 0), 0);
  const completed = recentScans.filter(s => s.status === 'completed').length;

  return (
    <div className="dashboard-page">
      <header className="dash-header">
        <div>
          <h1>Command Center</h1>
          <p className="text-fog text-sm">PentaVault — Automated VAPT Security Suite</p>
        </div>
        <Link to="/scan" className="btn btn-primary">⊕ New Scan</Link>
      </header>

      {/* Quick stats */}
      <div className="dash-stats">
        <div className="stat-chip">
          <span className="stat-value" style={{ color: 'var(--pv-cyan)' }}>{recentScans.length}</span>
          <span className="stat-label">Recent Scans</span>
        </div>
        <div className="stat-chip">
          <span className="stat-value" style={{ color: 'var(--pv-green)' }}>{completed}</span>
          <span className="stat-label">Completed</span>
        </div>
        <div className="stat-chip">
          <span className="stat-value" style={{ color: 'var(--sev-high)' }}>{totalFindings}</span>
          <span className="stat-label">Total Findings</span>
        </div>
      </div>

      {/* Quick launch */}
      <div className="glass-card">
        <h2>Quick Launch</h2>
        <p className="text-fog text-sm" style={{ marginBottom: 'var(--sp-4)' }}>
          Start a new vulnerability assessment scan against any target.
        </p>
        <div className="quick-modes">
          {['quick', 'full', 'web-only', 'network-only'].map(mode => (
            <Link key={mode} to={`/scan?mode=${mode}`} className="quick-mode-card">
              <strong>{mode.replace('-', ' ').replace(/\b\w/g, c => c.toUpperCase())}</strong>
              <span className="text-fog text-xs">
                {mode === 'quick' ? 'Fast web posture sweep' :
                 mode === 'full' ? 'Complete web + network' :
                 mode === 'web-only' ? 'Deep web application tests' :
                 'Recon + service exposure'}
              </span>
            </Link>
          ))}
        </div>
      </div>

      {/* Recent scans */}
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-4)' }}>
          <h2 style={{ margin: 0 }}>Recent Missions</h2>
          <Link to="/history" className="btn btn-ghost btn-sm">View All →</Link>
        </div>
        {loading ? (
          <div className="shimmer" style={{ height: 120, borderRadius: 'var(--radius-sm)' }} />
        ) : recentScans.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">🚀</span>
            <p>No scans yet. Launch your first mission!</p>
          </div>
        ) : (
          <div className="recent-scans-list">
            {recentScans.map(scan => {
              const statusClass = scan.status === 'completed' ? 'status-ok' :
                                  scan.status === 'failed' ? 'status-fail' :
                                  scan.status === 'running' ? 'status-run' : 'status-warn';
              return (
                <Link key={scan.scan_id} to={scan.status === 'running' ? `/scan/${scan.scan_id}/live` : `/scan/${scan.scan_id}/results`} className="recent-scan-row">
                  <div className={`scan-status-dot ${statusClass}`} />
                  <div className="scan-target truncate">{scan.target || 'Unknown'}</div>
                  <div className="scan-meta mono text-xs text-fog">{scan.mode || 'quick'}</div>
                  <div className="scan-meta mono text-xs">{scan.findings_count || 0} findings</div>
                  <div className="scan-meta text-xs text-fog">{scan.status}</div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
