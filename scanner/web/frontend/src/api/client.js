/* PentaVault v2.0 — API Client with SSE support */

const BASE = '';

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === 'string' ? detail : detail?.message || `HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

async function request(method, path, body = null) {
  const opts = { method, headers: {} };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new ApiError(res.status, data.detail || data);
  }
  return res.json();
}

/* ── REST endpoints ─────────────────────────────────────────────── */
export const startScan     = (payload) => request('POST', '/api/scan', payload);
export const getScan       = (id)      => request('GET',  `/api/scan/${id}`);
export const getScanFindings = (id)    => request('GET',  `/api/scan/${id}/findings`);
export const cancelScan    = (id)      => request('POST', `/api/scan/${id}/cancel`);
export const deleteScan    = (id)      => request('DELETE', `/api/scan/${id}`);
export const updateScan    = (id, d)   => request('PATCH', `/api/scan/${id}`, d);
export const listScans     = ()        => request('GET',  '/api/scans');
export const getMitreBreakdown = (id)  => request('GET',  `/api/scan/${id}/mitre`);
export const getOwaspRef   = ()        => request('GET',  '/api/owasp');
export const getMitreRef   = ()        => request('GET',  '/api/mitre');
export const getMitreTactics = ()      => request('GET',  '/api/mitre/tactics');
export const aiAnalyze     = (id)      => request('POST', '/api/ai/analyze', { scan_id: id });
export const aiRemediate   = (id, idx) => request('POST', '/api/ai/remediate', { scan_id: id, finding_index: idx });
export const aiExecSummary = (id)      => request('POST', '/api/ai/executive-summary', { scan_id: id });
export const aiMitreExplain = (body)   => request('POST', '/api/ai/mitre-explain', body);
export const getReportPdfUrl  = (id)   => `${BASE}/api/scan/${id}/report/pdf`;
export const getReportDocxUrl = (id)   => `${BASE}/api/scan/${id}/report/docx`;

/* ── SSE consumer for AI streams ────────────────────────────────── */
export function consumeAiStream(path, body, { onDelta, onFinal, onError }) {
  return new Promise((resolve, reject) => {
    fetch(BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(res => {
      if (!res.ok) {
        res.json().catch(() => ({})).then(d => {
          onError?.(d.detail || d);
          reject(new ApiError(res.status, d.detail || d));
        });
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      function pump() {
        reader.read().then(({ done, value }) => {
          if (done) { resolve(); return; }
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const payload = JSON.parse(line.slice(6));
                if (payload.event === 'delta')  onDelta?.(payload.data?.chunk || '');
                if (payload.event === 'final')  onFinal?.(payload.data);
                if (payload.event === 'error')  onError?.(payload.data);
              } catch (e) { /* skip malformed */ }
            }
          }
          pump();
        }).catch(reject);
      }
      pump();
    }).catch(reject);
  });
}

/* ── SSE consumer for scan progress ─────────────────────────────── */
export function subscribeScanProgress(scanId, { onProgress, onStageComplete, onFinding, onComplete, onError }) {
  const es = new EventSource(BASE + `/api/scan/${scanId}/stream`);
  es.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      switch (data.event) {
        case 'progress':        onProgress?.(data);     break;
        case 'stage_complete':  onStageComplete?.(data); break;
        case 'finding':         onFinding?.(data);       break;
        case 'complete':        onComplete?.(data);      es.close(); break;
        case 'failed':          onError?.(data);         es.close(); break;
        case 'cancelled':       onComplete?.(data);      es.close(); break;
        default: break;
      }
    } catch (e) { /* skip */ }
  };
  es.onerror = () => { onError?.({ message: 'Connection lost' }); };
  return () => es.close();
}
