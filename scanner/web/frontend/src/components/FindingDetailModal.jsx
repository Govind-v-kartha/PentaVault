import './FindingDetailModal.css';

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str || '');
  return d.innerHTML;
}

export default function FindingDetailModal({ finding, onClose, onAiRemediate, aiContent, aiStreaming, aiError }) {
  if (!finding) return null;

  const mitre = finding.mitre_attack || [];
  const cvss = Number(finding.cvss_score || 0);
  const sevClass = (finding.severity || 'None').toLowerCase();

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-panel" style={{ position: 'relative' }}>
        <button className="modal-close" onClick={onClose}>✕</button>

        <h2 style={{ marginBottom: 'var(--sp-2)', paddingRight: 40 }}>
          {finding.title || finding.type || finding.module || 'Finding'}
        </h2>

        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center', marginBottom: 'var(--sp-5)', flexWrap: 'wrap' }}>
          <span className={`sev-badge sev-${sevClass}`}>{finding.severity || 'None'}</span>
          <span className="mono text-sm text-fog">CVSS {cvss.toFixed(1)}</span>
          {finding.owasp_category && (
            <span className="mono text-xs text-fog">{finding.owasp_category}</span>
          )}
        </div>

        {/* CVSS Gauge */}
        <div className="cvss-gauge-bar">
          <div className="cvss-fill" style={{ width: `${(cvss / 10) * 100}%` }} data-sev={sevClass} />
          <span className="cvss-label">{cvss.toFixed(1)} / 10.0</span>
        </div>

        {/* Detail fields */}
        <div className="modal-fields">
          <Field label="URL / Path" value={finding.affected_url || finding.url || finding.path} />
          <Field label="Parameter" value={finding.parameter || finding.param} />
          <Field label="Detail" value={finding.detail || finding.issue} />
          {finding.payload && <Field label="Payload" value={finding.payload} mono />}
          <Field label="Evidence" value={finding.evidence} />
          <Field label="Recommendation" value={finding.remediation || finding.recommendation} />
          {finding.cvss_vector && <Field label="CVSS Vector" value={finding.cvss_vector} mono />}

          {/* MITRE ATT&CK */}
          {mitre.length > 0 && (
            <div className="modal-field">
              <div className="mf-label">MITRE ATT&CK</div>
              <div className="mf-value">
                {mitre.map((mt, i) => (
                  <div key={i} className="mitre-card-mini">
                    <a href={mt.url} target="_blank" rel="noopener noreferrer">
                      {mt.technique} — {mt.name}
                    </a>
                    <span className={`conf-dot conf-${(mt.confidence || 'medium').toLowerCase()}`} />
                    <span className="text-xs text-fog">{mt.tactic}</span>
                    {mt.detection && <div className="text-xs text-fog" style={{ marginTop: 4 }}>Detection: {mt.detection}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Kill Chain */}
          {finding.mitre_kill_chain?.length > 0 && (
            <Field label="Kill Chain" value={finding.mitre_kill_chain.join(' → ')} />
          )}
        </div>

        {/* AI Remediation */}
        <div className="modal-ai-section">
          <button className="btn btn-ai" onClick={onAiRemediate} disabled={aiStreaming}>
            🧠 {aiStreaming ? 'Generating...' : 'AI Remediation Guide'}
          </button>
          {aiError && <div className="ai-error">{aiError}</div>}
          {aiContent && (
            <div className={`ai-content ${aiStreaming ? 'ai-streaming' : ''}`} dangerouslySetInnerHTML={{ __html: aiContent }} />
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono }) {
  if (!value) return null;
  return (
    <div className="modal-field">
      <div className="mf-label">{label}</div>
      <div className={`mf-value ${mono ? 'mono' : ''}`}>{String(value)}</div>
    </div>
  );
}
