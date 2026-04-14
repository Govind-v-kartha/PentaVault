import { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan, getMitreBreakdown, aiAnalyze, aiExecSummary, aiRemediate, getReportPdfUrl, getReportDocxUrl } from '../api/client';
import { markdownToHtml } from '../utils/markdown';
import SeverityDonut from '../components/SeverityDonut';
import OwaspBarChart from '../components/OwaspBarChart';
import MitreHeatmap from '../components/MitreHeatmap';
import FindingDetailModal from '../components/FindingDetailModal';
import './ResultsPage.css';

export default function ResultsPage() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Filters
  const [searchText, setSearchText] = useState('');
  const [sevFilter, setSevFilter] = useState('');

  // AI state
  const [aiAnalysis, setAiAnalysis] = useState('');
  const [aiExec, setAiExec] = useState('');
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState(false);
  const [aiExecLoading, setAiExecLoading] = useState(false);
  const [aiRemContent, setAiRemContent] = useState('');
  const [aiRemLoading, setAiRemLoading] = useState(false);
  const [aiRemError, setAiRemError] = useState('');

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    Promise.all([
      getScan(id),
      getMitreBreakdown(id).catch(() => null),
    ]).then(([scanData, mitre]) => {
      setScan(scanData);
      setMitreData(mitre);
    }).catch(() => {})
    .finally(() => setLoading(false));
  }, [id]);

  const findings = useMemo(() => scan?.findings || [], [scan]);
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (sevFilter && f.severity !== sevFilter) return false;
      if (searchText) {
        const hay = JSON.stringify(f).toLowerCase();
        if (!hay.includes(searchText.toLowerCase())) return false;
      }
      return true;
    });
  }, [findings, sevFilter, searchText]);

  // Severity counts
  const sevCounts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }, [findings]);

  // Stage timing
  const stages = scan?.stages || [];

  function aiErrorHtml(e) {
    const msg = e.message || String(e);
    if (msg.includes('unavailable') || msg.includes('retry') || msg.includes('502') || msg.includes('exhausted'))
      return `<div class="ai-error"><strong>⏳ AI Temporarily Unavailable</strong><p>All API keys are rate-limited. Please wait a few minutes and try again.</p></div>`;
    return `<div class="ai-error"><strong>❌ AI Error</strong><p>${msg}</p></div>`;
  }

  async function runAiAnalysis() {
    setAiAnalysisLoading(true);
    try {
      const res = await aiAnalyze(id);
      const raw = res.analysis || res.result || 'No analysis returned.';
      setAiAnalysis(markdownToHtml(raw));
    } catch (e) {
      setAiAnalysis(aiErrorHtml(e));
    } finally { setAiAnalysisLoading(false); }
  }

  async function runAiExec() {
    setAiExecLoading(true);
    try {
      const res = await aiExecSummary(id);
      const raw = res.summary || res.result || 'No summary returned.';
      setAiExec(markdownToHtml(raw));
    } catch (e) {
      setAiExec(aiErrorHtml(e));
    } finally { setAiExecLoading(false); }
  }

  async function handleAiRemediate() {
    if (!selectedFinding) return;
    const idx = findings.indexOf(selectedFinding);
    if (idx < 0) return;
    setAiRemLoading(true);
    setAiRemError('');
    setAiRemContent('');
    try {
      const res = await aiRemediate(id, idx);
      const raw = res.remediation || res.result || 'No remediation returned.';
      setAiRemContent(markdownToHtml(raw));
    } catch (e) {
      setAiRemError(e.message);
    } finally { setAiRemLoading(false); }
  }

  const formatTime = (s) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  if (loading) {
    return (
      <div className="results-page">
        <div className="shimmer" style={{ height: 120, borderRadius: 16, marginBottom: 20 }} />
        <div className="shimmer" style={{ height: 300, borderRadius: 16 }} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="results-page">
        <div className="empty-state">
          <span className="empty-icon">❓</span>
          <p>Scan not found.</p>
          <Link to="/history" className="btn btn-ghost">View History</Link>
        </div>
      </div>
    );
  }

  const coverage = mitreData?.matrix_coverage || {};
  const narrative = mitreData?.threat_narrative;
  const elapsedTotal = scan.elapsed ? Math.round(scan.elapsed) : 0;
  const statusLabel = scan.status === 'completed' ? '✓ Completed' : scan.status === 'failed' ? '✕ Failed' : scan.status;

  return (
    <div className="results-page">
      {/* ── Hero ribbon ─────────────────────────────────────────── */}
      <div className="results-hero glass-card">
        <div className="hero-left">
          <h1>Mission Results</h1>
          <div className="hero-meta">
            <span className="mono text-sm">{scan.target}</span>
            <span className="meta-chip mono">{(scan.mode || 'quick').toUpperCase()}</span>
            <span className="meta-chip mono">{statusLabel}</span>
            <span className="meta-chip mono">{formatTime(elapsedTotal)}</span>
          </div>
        </div>
        <div className="hero-actions">
          <a href={getReportPdfUrl(id)} className="btn btn-ghost btn-sm" target="_blank" rel="noopener">📄 PDF</a>
          <a href={getReportDocxUrl(id)} className="btn btn-ghost btn-sm" target="_blank" rel="noopener">📃 DOCX</a>
          <a href={`/api/scan/${id}/report/json`} className="btn btn-ghost btn-sm" download>📋 JSON</a>
        </div>
      </div>

      {/* ── Severity stats ──────────────────────────────────────── */}
      <div className="severity-stats">
        {['Critical','High','Medium','Low','Info'].map(sev => (
          <button key={sev} className={`stat-chip clickable ${sevFilter === sev ? 'active' : ''}`}
            onClick={() => setSevFilter(prev => prev === sev ? '' : sev)}>
            <span className="stat-value" style={{ color: `var(--sev-${sev.toLowerCase()})` }}>
              {sevCounts[sev] || 0}
            </span>
            <span className="stat-label">{sev}</span>
          </button>
        ))}
      </div>

      {/* ── Charts row ──────────────────────────────────────────── */}
      <div className="charts-row">
        <div className="glass-card chart-card">
          <h3>Severity Distribution</h3>
          <SeverityDonut findings={findings} />
        </div>
        <div className="glass-card chart-card">
          <h3>OWASP Categories</h3>
          <OwaspBarChart findings={findings} />
        </div>
      </div>

      {/* ── MITRE heatmap ───────────────────────────────────────── */}
      <div className="glass-card">
        <h3>MITRE ATT&CK Coverage</h3>
        <MitreHeatmap coverage={coverage} />
      </div>

      {/* ── Threat narrative ────────────────────────────────────── */}
      {narrative && narrative.finding_count > 0 && (
        <div className="glass-card threat-narrative">
          <div className="narrative-header">
            <h3>Threat Narrative</h3>
            <span className={`risk-badge risk-${narrative.risk_color}`}>{narrative.risk_level} RISK</span>
          </div>
          <div className="text-sm" style={{ lineHeight: 1.65 }} dangerouslySetInnerHTML={{ __html: narrative.narrative }} />
          <div className="narrative-meta">
            <span className="meta-chip">{narrative.finding_count} findings</span>
            <span className="meta-chip">{narrative.techniques_matched} techniques</span>
            <span className="meta-chip">{narrative.tactics_covered}/14 tactics</span>
          </div>
        </div>
      )}

      {/* ── Stage timing ────────────────────────────────────────── */}
      {stages.length > 0 && (
        <div className="glass-card">
          <h3>Stage Timing</h3>
          <div className="stage-timing">
            {stages.map((s, i) => {
              const max = Math.max(...stages.map(st => Number(st.time || 0)), 1);
              const pct = (Number(s.time || 0) / max) * 100;
              return (
                <div key={i} className="timing-row">
                  <span className="timing-name">{s.name}</span>
                  <div className="timing-bar-track">
                    <div className="timing-bar-fill" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="timing-value mono">{s.time}s</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── AI Analysis ─────────────────────────────────────────── */}
      <div className="ai-row">
        <div className="glass-card flex-1">
          <div className="ai-card-header">
            <h3>🧠 AI Threat Analysis</h3>
            <button className="btn btn-ai btn-sm" onClick={runAiAnalysis} disabled={aiAnalysisLoading}>
              {aiAnalysisLoading ? '⟳ Analyzing...' : 'Generate'}
            </button>
          </div>
          {aiAnalysis ? (
            <div className="ai-content" dangerouslySetInnerHTML={{ __html: aiAnalysis }} />
          ) : (
            <p className="text-fog text-sm">Click Generate to create an AI-powered threat analysis of these findings.</p>
          )}
        </div>
        <div className="glass-card flex-1">
          <div className="ai-card-header">
            <h3>📋 Executive Summary</h3>
            <button className="btn btn-ai btn-sm" onClick={runAiExec} disabled={aiExecLoading}>
              {aiExecLoading ? '⟳ Writing...' : 'Generate'}
            </button>
          </div>
          {aiExec ? (
            <div className="ai-content" dangerouslySetInnerHTML={{ __html: aiExec }} />
          ) : (
            <p className="text-fog text-sm">Click Generate to create a management-ready executive summary.</p>
          )}
        </div>
      </div>

      {/* ── Findings table ──────────────────────────────────────── */}
      <div className="glass-card">
        <div className="findings-header">
          <h3>Findings ({filteredFindings.length})</h3>
          <div className="findings-controls">
            <input className="input" type="text" placeholder="Search findings..."
              value={searchText} onChange={e => setSearchText(e.target.value)}
              style={{ maxWidth: 260 }} />
            <select className="input select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}
              style={{ maxWidth: 160 }}>
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>URL / Path</th>
                <th>OWASP</th>
                <th>CVSS</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.slice(0, 200).map((f, i) => {
                const path = f.affected_url || f.url || f.path || '-';
                return (
                  <tr key={i} onClick={() => { setSelectedFinding(f); setAiRemContent(''); setAiRemError(''); }}>
                    <td><span className={`sev-badge sev-${(f.severity||'none').toLowerCase()}`}>{f.severity||'Info'}</span></td>
                    <td className="truncate" style={{ maxWidth: 180 }}>{f.title || f.type || f.module || '-'}</td>
                    <td className="truncate mono text-xs" style={{ maxWidth: 200 }} title={path}>{path.length > 50 ? '...'+path.slice(-47) : path}</td>
                    <td className="text-xs truncate" style={{ maxWidth: 140 }}>{(f.owasp_category || '-').slice(0, 30)}</td>
                    <td className="mono">{f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : '-'}</td>
                    <td className="truncate text-xs" style={{ maxWidth: 200 }}>{(f.detail || f.payload || '-').slice(0, 60)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {filteredFindings.length > 200 && (
            <p className="text-fog text-xs" style={{ padding: 'var(--sp-3)', textAlign: 'center' }}>
              Showing 200 of {filteredFindings.length} findings. Use search/filter to narrow.
            </p>
          )}
        </div>
      </div>

      {/* ── Finding detail modal ────────────────────────────────── */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onAiRemediate={handleAiRemediate}
          aiContent={aiRemContent}
          aiStreaming={aiRemLoading}
          aiError={aiRemError}
        />
      )}
    </div>
  );
}
