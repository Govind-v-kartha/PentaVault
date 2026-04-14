import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScan } from '../api/client';
import ProgressRing from '../components/ProgressRing';
import './LiveScanPage.css';

const MODULES = [
  'SQLi','XSS','Headers','SSRF','IDOR','Open Redirect','Command Injection',
  'XXE','LFI','Sensitive Files','NoSQLi','SSTI','GraphQL Abuse','JWT Checks',
  'Host Header','CORS','HPP','CRLF Injection','Request Smuggling',
  'Mass Assignment','Insecure Deser.','Prototype Pollution','CSV Injection',
];

const STAGES = ['Target Input','Reconnaissance','Fingerprinting','Web Crawling','Vulnerability Testing','CVSS Scoring','Report Generation'];

export default function LiveScanPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [liveFindings, setLiveFindings] = useState([]);
  const [elapsed, setElapsed] = useState(0);
  const pollRef = useRef(null);
  const timerRef = useRef(null);
  const startTimeRef = useRef(Date.now());
  const prevFindingsCount = useRef(0);

  // Poll for scan data
  useEffect(() => {
    if (!id) return;
    const poll = async () => {
      try {
        const data = await getScan(id);
        setScan(data);

        // Track new findings for the live feed
        const findings = data.findings || [];
        if (findings.length > prevFindingsCount.current) {
          const newOnes = findings.slice(prevFindingsCount.current);
          setLiveFindings(prev => [...prev, ...newOnes].slice(-30));
          prevFindingsCount.current = findings.length;
        }

        if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          // Auto-redirect to results after brief delay
          if (data.status === 'completed') {
            setTimeout(() => navigate(`/scan/${id}/results`, { replace: true }), 1500);
          }
        }
      } catch (e) { /* retry */ }
    };
    poll();
    pollRef.current = setInterval(poll, 1200);
    return () => clearInterval(pollRef.current);
  }, [id, navigate]);

  // Local timer for smooth elapsed display
  useEffect(() => {
    startTimeRef.current = Date.now();
    timerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 250);
    return () => clearInterval(timerRef.current);
  }, []);

  const progress = scan?.progress || 0;
  const stage = scan?.current_stage || 'Initialising...';
  const findingsCount = scan?.findings_count || 0;
  const status = scan?.status || 'running';
  const stages = scan?.stages || [];
  const moduleResults = scan?.module_results || {};

  // Determine current stage index
  const currentStageIdx = STAGES.findIndex(s =>
    stage.toLowerCase().includes(s.toLowerCase())
  );

  const formatTime = (s) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  const isDone = status !== 'running';

  return (
    <div className="live-scan-page">
      {/* Ambient background effects */}
      <div className="ambient-bg">
        <div className="radar-sweep" />
        <div className="scan-grid" />
        {!isDone && <div className="scan-pulse" />}
      </div>

      <div className="live-content">
        {/* Header */}
        <div className="live-header">
          <div className="live-status-badge" data-status={status}>
            <span className="status-dot" />
            {status === 'running' ? 'SCANNING' : status.toUpperCase()}
          </div>
          <div className="live-target mono">{scan?.target || '...'}</div>
        </div>

        {/* Central progress ring */}
        <div className="live-ring-section">
          <ProgressRing progress={progress} size={200} strokeWidth={12} />
          <div className="live-stage-label">{stage}</div>
          <div className="live-meta-row">
            <span className="meta-chip mono">{formatTime(elapsed)}</span>
            <span className="meta-chip mono">{findingsCount} findings</span>
            <span className="meta-chip mono">{scan?.mode || 'quick'}</span>
          </div>
        </div>

        {/* Stage pipeline */}
        <div className="glass-card stage-pipeline">
          <h3>Pipeline Stages</h3>
          <div className="pipeline-track">
            {STAGES.map((s, i) => {
              const completed = stages.some(st => st.name?.toLowerCase().includes(s.toLowerCase()));
              const active = i === currentStageIdx && !isDone;
              const stageData = stages.find(st => st.name?.toLowerCase().includes(s.toLowerCase()));
              return (
                <div key={s} className={`pipeline-node ${completed ? 'done' : ''} ${active ? 'active' : ''}`}>
                  <div className="pipeline-dot" />
                  <div className="pipeline-label">{s}</div>
                  {stageData && <div className="pipeline-time">{stageData.time}s</div>}
                </div>
              );
            })}
          </div>
        </div>

        {/* Two-column: module grid + live feed */}
        <div className="live-grid-2col">
          {/* Module status grid */}
          <div className="glass-card">
            <h3>Module Status</h3>
            <div className="module-grid">
              {MODULES.map(mod => {
                const result = moduleResults[mod];
                const isDone = result !== undefined;
                const hasFindings = isDone && result > 0;
                return (
                  <div key={mod} className={`module-cell ${isDone ? 'done' : ''} ${hasFindings ? 'has-findings' : ''}`}>
                    <span className="module-name">{mod}</span>
                    {isDone && <span className="module-count">{result}</span>}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live finding feed */}
          <div className="glass-card">
            <h3>Live Finding Feed</h3>
            <div className="finding-feed">
              {liveFindings.length === 0 ? (
                <div className="feed-empty text-fog text-sm">
                  {status === 'running' ? 'Waiting for findings...' : 'No findings discovered.'}
                </div>
              ) : (
                liveFindings.map((f, i) => (
                  <div key={i} className="feed-item" style={{ animationDelay: `${(i % 5) * 0.05}s` }}>
                    <span className={`sev-badge sev-${(f.severity || 'none').toLowerCase()}`}>
                      {f.severity || 'Info'}
                    </span>
                    <span className="feed-type">{f.title || f.type || f.module || 'Finding'}</span>
                    <span className="feed-detail truncate">{(f.detail || f.payload || '').slice(0, 80)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Completion banner */}
        {isDone && (
          <div className={`completion-banner ${status}`}>
            <span className="completion-icon">
              {status === 'completed' ? '✓' : status === 'cancelled' ? '⊘' : '✕'}
            </span>
            <div>
              <strong>
                {status === 'completed' ? 'Mission Complete' : status === 'cancelled' ? 'Mission Aborted' : 'Mission Failed'}
              </strong>
              <p className="text-sm">{findingsCount} findings discovered in {formatTime(elapsed)}</p>
              {status === 'completed' && <p className="text-xs text-fog">Redirecting to results...</p>}
            </div>
            {status !== 'completed' && (
              <button className="btn btn-ghost" onClick={() => navigate(`/scan/${id}/results`)}>
                View Results →
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
