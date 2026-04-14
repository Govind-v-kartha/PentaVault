import { useEffect, useState } from 'react';
import { getOwaspRef } from '../api/client';
import './OwaspPage.css';

export default function OwaspPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getOwaspRef()
      .then(d => setData(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const entries = data ? (Array.isArray(data) ? data : Object.entries(data)) : [];

  return (
    <div className="owasp-page">
      <header className="owasp-header">
        <h1>OWASP Top 10 — 2025</h1>
        <p className="text-fog text-sm">Web application security risk reference.</p>
      </header>

      {loading ? (
        <div className="glass-card"><div className="shimmer" style={{ height: 300 }} /></div>
      ) : !data || entries.length === 0 ? (
        <div className="glass-card">
          <div className="empty-state">
            <span className="empty-icon">⊞</span>
            <p>OWASP reference data unavailable.</p>
          </div>
        </div>
      ) : (
        <div className="owasp-grid">
          {entries.map((entry, i) => {
            const id = Array.isArray(entry) ? entry[0] : entry.id || entry.category || `A${String(i+1).padStart(2,'0')}`;
            const info = Array.isArray(entry) ? entry[1] : entry;
            const name = info?.name || info?.title || id;
            const desc = info?.description || info?.summary || '';
            const color = i < 3 ? 'var(--sev-critical)' : i < 6 ? 'var(--sev-high)' : i < 8 ? 'var(--sev-medium)' : 'var(--sev-low)';

            return (
              <div key={id} className="glass-card owasp-card">
                <div className="owasp-card-top">
                  <span className="owasp-id" style={{ color }}>{id}</span>
                  <span className="owasp-rank">#{i + 1}</span>
                </div>
                <h3 className="owasp-name">{name}</h3>
                {desc && <p className="owasp-desc text-sm text-fog">{String(desc).slice(0, 250)}</p>}
                {info?.url && (
                  <a href={info.url} target="_blank" rel="noopener noreferrer" className="text-xs">
                    Learn more →
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
