import { useEffect, useState } from 'react';
import { getMitreRef } from '../api/client';
import './MitrePage.css';

export default function MitrePage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [expandedTactics, setExpandedTactics] = useState(new Set());

  useEffect(() => {
    getMitreRef()
      .then(d => setData(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const toggleTactic = (tactic) => {
    setExpandedTactics(prev => {
      const next = new Set(prev);
      next.has(tactic) ? next.delete(tactic) : next.add(tactic);
      return next;
    });
  };

  const expandAll = () => {
    if (!data) return;
    const all = new Set();
    Object.keys(data).forEach(k => all.add(k));
    setExpandedTactics(all);
  };

  const collapseAll = () => setExpandedTactics(new Set());

  const searchLower = search.toLowerCase();
  const filterEntries = (entries) => {
    if (!searchLower) return entries;
    return Object.entries(entries || {}).filter(([id, info]) => {
      const hay = `${id} ${info?.name || ''} ${info?.description || ''}`.toLowerCase();
      return hay.includes(searchLower);
    });
  };

  return (
    <div className="mitre-page">
      <header className="mitre-header">
        <div>
          <h1>MITRE ATT&CK Reference</h1>
          <p className="text-fog text-sm">Enterprise tactics and techniques knowledge base.</p>
        </div>
      </header>

      <div className="mitre-toolbar">
        <input className="input" type="text" placeholder="Search techniques..."
          value={search} onChange={e => setSearch(e.target.value)}
          style={{ maxWidth: 320 }} />
        <div className="toolbar-btns">
          <button className="btn btn-ghost btn-sm" onClick={expandAll}>Expand All</button>
          <button className="btn btn-ghost btn-sm" onClick={collapseAll}>Collapse All</button>
        </div>
      </div>

      {loading ? (
        <div className="glass-card"><div className="shimmer" style={{ height: 300 }} /></div>
      ) : !data ? (
        <div className="glass-card"><div className="empty-state"><span className="empty-icon">⬡</span><p>MITRE data unavailable.</p></div></div>
      ) : (
        <div className="mitre-list">
          {Object.entries(data).map(([tactic, techniques]) => {
            const filtered = filterEntries(techniques);
            if (searchLower && filtered.length === 0) return null;
            const isExpanded = expandedTactics.has(tactic);

            return (
              <div key={tactic} className="glass-card mitre-tactic-card">
                <button className="tactic-header" onClick={() => toggleTactic(tactic)}>
                  <span className="tactic-chevron">{isExpanded ? '▾' : '▸'}</span>
                  <span className="tactic-name">{tactic}</span>
                  <span className="tactic-count mono text-xs text-fog">
                    {Object.keys(techniques || {}).length} techniques
                  </span>
                </button>
                {isExpanded && (
                  <div className="technique-list">
                    {(searchLower ? filtered : Object.entries(techniques || {})).map(([id, info]) => (
                      <div key={id} className="technique-item">
                        <a href={info?.url || `https://attack.mitre.org/techniques/${id.replace('.','/')}`}
                          target="_blank" rel="noopener noreferrer" className="tech-id mono">{id}</a>
                        <span className="tech-name">{info?.name || id}</span>
                        {info?.description && (
                          <p className="tech-desc text-xs text-fog">{String(info.description).slice(0, 150)}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
