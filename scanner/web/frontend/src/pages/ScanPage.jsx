import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { startScan } from '../api/client';
import './ScanPage.css';

const MODES = [
  { value: 'quick', label: 'Quick', desc: 'Fast web posture sweep' },
  { value: 'full', label: 'Full', desc: 'Complete web + network pass' },
  { value: 'web-only', label: 'Web Only', desc: 'Deep application-layer tests' },
  { value: 'network-only', label: 'Network Only', desc: 'Recon + service exposure' },
];

export default function ScanPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [form, setForm] = useState({
    target: '',
    mode: params.get('mode') || 'quick',
    threads: 5,
    timeout: 10,
    requestDelay: 0,
    cookie: '',
    crawlMode: 'auto',
    useBrowser: false,
  });
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState('');

  const update = (field, value) => setForm(prev => ({ ...prev, [field]: value }));

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.target.trim()) return;
    setLaunching(true);
    setError('');

    try {
      const res = await startScan({
        target: form.target.trim(),
        mode: form.mode,
        threads: Number(form.threads),
        timeout: Number(form.timeout),
        request_delay: Number(form.requestDelay),
        cookie: form.cookie.trim() || null,
        use_browser: form.useBrowser,
        crawl_mode: form.crawlMode,
      });
      navigate(`/scan/${res.scan_id}/live`);
    } catch (err) {
      const detail = err.detail;
      if (detail && typeof detail === 'object') {
        const msgs = [...(detail.errors || []), ...(detail.warnings || [])];
        setError(msgs.join('\n') || err.message);
      } else {
        setError(typeof detail === 'string' ? detail : err.message || 'Failed to start scan');
      }
      setLaunching(false);
    }
  }

  return (
    <div className="scan-page">
      <header className="scan-header">
        <h1>Launch Mission</h1>
        <p className="text-fog text-sm">Configure and deploy a new vulnerability assessment scan.</p>
      </header>

      <form onSubmit={handleSubmit} className="glass-card scan-form">
        <div className="form-field">
          <label className="label" htmlFor="target">Target URL / IP</label>
          <input
            id="target"
            className="input"
            type="text"
            placeholder="https://example.com"
            value={form.target}
            onChange={e => update('target', e.target.value)}
            required
            autoFocus
          />
        </div>

        <div className="form-field">
          <label className="label">Scan Mode</label>
          <div className="mode-grid">
            {MODES.map(m => (
              <button
                key={m.value}
                type="button"
                className={`mode-card ${form.mode === m.value ? 'active' : ''}`}
                onClick={() => update('mode', m.value)}
              >
                <strong>{m.label}</strong>
                <span>{m.desc}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="form-row-group">
          <div className="form-field">
            <label className="label" htmlFor="threads">Threads</label>
            <input id="threads" className="input" type="number" min="1" max="10"
              value={form.threads} onChange={e => update('threads', e.target.value)} />
          </div>
          <div className="form-field">
            <label className="label" htmlFor="timeout">Timeout (s)</label>
            <input id="timeout" className="input" type="number" min="1" max="60"
              value={form.timeout} onChange={e => update('timeout', e.target.value)} />
          </div>
          <div className="form-field">
            <label className="label" htmlFor="delay">Request Delay (s)</label>
            <input id="delay" className="input" type="number" min="0" max="2" step="0.1"
              value={form.requestDelay} onChange={e => update('requestDelay', e.target.value)} />
          </div>
        </div>

        <div className="form-field">
          <label className="label" htmlFor="cookie">Cookie (optional)</label>
          <input id="cookie" className="input" type="text" placeholder="session=abc123"
            value={form.cookie} onChange={e => update('cookie', e.target.value)} />
        </div>

        <div className="form-row-group">
          <div className="form-field">
            <label className="label" htmlFor="crawl">Crawl Mode</label>
            <select id="crawl" className="input select" value={form.crawlMode}
              onChange={e => update('crawlMode', e.target.value)}>
              <option value="auto">Auto</option>
              <option value="httpx">HTTP</option>
              <option value="selenium">Selenium</option>
              <option value="hybrid">Hybrid</option>
            </select>
          </div>
          <div className="form-field" style={{ display: 'flex', alignItems: 'flex-end', paddingBottom: 4 }}>
            <label className="toggle">
              <input type="checkbox" checked={form.useBrowser} onChange={e => update('useBrowser', e.target.checked)} />
              <span className="toggle-track" />
            </label>
            <span className="text-fog text-sm" style={{ marginLeft: 'var(--sp-3)' }}>Selenium Browser Engine</span>
          </div>
        </div>

        {error && (
          <div className="scan-error">{error}</div>
        )}

        <button type="submit" className="btn btn-primary launch-btn" disabled={launching || !form.target.trim()}>
          {launching ? '⟳ Launching...' : '⊕ Launch Scan'}
        </button>
      </form>
    </div>
  );
}
