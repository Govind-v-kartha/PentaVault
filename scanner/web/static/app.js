/* ── PentaVault — Dashboard JavaScript ──────────────────────────── */

const API = '';  // Same origin
let activeScanId = null;
let pollTimer = null;
let allFindings = [];
let scanTimerInterval = null;
let scanStartTime = null;

const MAX_THREADS = 10;

// ── Live Timer Helper ───────────────────────────────────────────
function formatDuration(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}

function startScanTimer() {
  scanStartTime = Date.now();
  if (scanTimerInterval) clearInterval(scanTimerInterval);
  scanTimerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    document.getElementById('elapsed').textContent = formatDuration(elapsed);
  }, 250);
}

function stopScanTimer() {
  if (scanTimerInterval) {
    clearInterval(scanTimerInterval);
    scanTimerInterval = null;
  }
}

// ── Tab navigation ──────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');

    if (btn.dataset.tab === 'history') loadHistory();
    if (btn.dataset.tab === 'owasp') loadOwaspRef();
    if (btn.dataset.tab === 'mitre') loadMitreRef();
  });
});

// ── Start Scan ──────────────────────────────────────────────────
document.getElementById('scanForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const target = document.getElementById('target').value.trim();
  if (!target) return;

  let threads = parseInt(document.getElementById('threads').value);
  if (threads > MAX_THREADS) {
    threads = MAX_THREADS;
    document.getElementById('threads').value = MAX_THREADS;
    alert(`Thread limit capped to ${MAX_THREADS} for stability.`);
  }

  const body = {
    target,
    mode: document.getElementById('mode').value,
    threads,
    timeout: parseFloat(document.getElementById('timeout').value),
    cookie: document.getElementById('cookie').value.trim() || null,
    use_browser: document.getElementById('useBrowser').checked,
  };

  const btn = document.getElementById('btnStart');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  document.getElementById('progressCard').style.display = '';
  document.getElementById('resultsPanel').style.display = 'none';
  document.getElementById('progressStage').textContent = 'Initialising…';
  document.getElementById('progressPct').textContent = '0%';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('elapsed').textContent = '0s';
  document.getElementById('findingsCount').textContent = '0';
  document.getElementById('stageTimeline').innerHTML = '';
  document.getElementById('totalTimeDisplay').style.display = 'none';
  startScanTimer();

  try {
    const res = await fetch(API + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Server returned ' + res.status);
    }
    const data = await res.json();
    activeScanId = data.scan_id;
    startPolling();
  } catch (err) {
    alert('Failed to start scan: ' + err.message);
    btn.disabled = false;
    btn.textContent = 'Start Scan';
    stopScanTimer();
  }
});

// ── Poll scan progress ──────────────────────────────────────────
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollScan, 1000);
}

async function pollScan() {
  if (!activeScanId) return;

  try {
    const res = await fetch(API + '/api/scan/' + activeScanId);
    const data = await res.json();

    // Update progress UI
    document.getElementById('progressStage').textContent = data.current_stage;
    document.getElementById('progressPct').textContent = data.progress + '%';
    document.getElementById('progressFill').style.width = data.progress + '%';
    document.getElementById('elapsed').textContent = data.elapsed + 's';
    document.getElementById('findingsCount').textContent = data.findings_count || 0;

    // Stage chips
    const timeline = document.getElementById('stageTimeline');
    timeline.innerHTML = data.stages.map(s =>
      `<span class="stage-chip done">${s.name} (${s.time}s)</span>`
    ).join('');

    if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
      clearInterval(pollTimer);
      pollTimer = null;
      stopScanTimer();

      const totalElapsed = scanStartTime ? Math.floor((Date.now() - scanStartTime) / 1000) : Math.round(data.elapsed);
      const totalTimeStr = formatDuration(totalElapsed);
      document.getElementById('elapsed').textContent = totalTimeStr;

      // Show total time prominently
      const totalTimeEl = document.getElementById('totalTimeDisplay');
      const statusLabel = data.status === 'completed' ? 'Scan completed' : data.status === 'cancelled' ? 'Scan cancelled' : 'Scan failed';
      totalTimeEl.innerHTML = `<span class="total-time-icon">&#9201;</span> ${statusLabel} in <strong>${totalTimeStr}</strong>`;
      totalTimeEl.className = 'total-time-display status-' + data.status;
      totalTimeEl.style.display = '';

      const btn = document.getElementById('btnStart');
      btn.disabled = false;
      btn.textContent = 'Start Scan';

      if (data.status === 'completed' || (data.findings && data.findings.length > 0)) {
        showResults(data);
      } else if (data.status === 'cancelled') {
        document.getElementById('progressStage').textContent = 'Scan cancelled';
      } else {
        document.getElementById('progressStage').textContent = 'Failed: ' + (data.error || 'Unknown error');
      }
    }
  } catch (err) {
    console.error('Poll error:', err);
    // Re-enable button if polling fails repeatedly
    clearInterval(pollTimer);
    pollTimer = null;
    stopScanTimer();
    const btn = document.getElementById('btnStart');
    btn.disabled = false;
    btn.textContent = 'Start Scan';
  }
}

// ── Show Results ────────────────────────────────────────────────
function showResults(data) {
  const findings = data.findings || [];
  allFindings = findings;

  document.getElementById('resultsPanel').style.display = '';

  // Severity counts
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
  findings.forEach(f => {
    const sev = f.severity || 'None';
    if (sev in counts) counts[sev]++;
    else counts.None++;
  });

  document.getElementById('statCritical').textContent = counts.Critical;
  document.getElementById('statHigh').textContent = counts.High;
  document.getElementById('statMedium').textContent = counts.Medium;
  document.getElementById('statLow').textContent = counts.Low;
  document.getElementById('statInfo').textContent = counts.None;
  document.getElementById('totalBadge').textContent = findings.length;

  // OWASP breakdown
  const owaspCounts = {};
  findings.forEach(f => {
    const cat = f.owasp_category || 'Unknown';
    owaspCounts[cat] = (owaspCounts[cat] || 0) + 1;
  });
  const maxOwasp = Math.max(...Object.values(owaspCounts), 1);
  const owaspColors = { Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)' };

  const owaspHtml = Object.entries(owaspCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => {
      const pct = (count / maxOwasp) * 100;
      return `<div class="owasp-row">
        <span class="label" title="${cat}">${cat}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--accent)"></div></div>
        <span class="count">${count}</span>
      </div>`;
    }).join('');
  document.getElementById('owaspBreakdown').innerHTML = owaspHtml;

  // MITRE ATT&CK breakdown — enhanced with confidence, matrix heatmap, attack paths
  renderMitreBreakdown(findings, data);

  // Findings table
  renderFindings(findings);

  // Stage timing
  const stages = data.stages || [];
  const maxTime = Math.max(...stages.map(s => s.time), 1);
  document.getElementById('stageTiming').innerHTML = stages.map(s => {
    const pct = (s.time / maxTime) * 100;
    return `<div class="timing-row">
      <span class="name">${s.name}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <span class="time">${s.time}s</span>
    </div>`;
  }).join('');
}

// ── Render Findings Table ───────────────────────────────────────
function renderFindings(findings) {
  const tbody = document.getElementById('findingsBody');
  tbody.innerHTML = findings.map((f, i) => {
    const sev = f.severity || 'None';
    const cvss = f.cvss_score != null ? f.cvss_score.toFixed(1) : '-';
    const path = f.url || f.path || '-';
    const shortPath = path.length > 60 ? '...' + path.slice(-57) : path;
    const owasp = (f.owasp_category || '').replace(/^(A\d+):?\d*\s*-?\s*/, '$1 - ').substring(0, 35);
    const detail = f.detail || f.payload || f.issue || '-';
    const shortDetail = detail.length > 50 ? detail.substring(0, 47) + '...' : detail;
    const mitreList = (f.mitre_attack || []);
    const mitreTxt = mitreList.map(mt => mt.technique).join(', ') || '-';
    const topConf = mitreList.length > 0 ? mitreList[0].confidence || 'medium' : '';
    const confDot = topConf ? `<span class="conf-dot conf-${topConf}" title="${topConf} confidence"></span>` : '';

    return `<tr data-idx="${i}">
      <td><span class="sev-badge sev-${sev}">${sev}</span></td>
      <td>${escHtml(f.type || f.module || '-')}</td>
      <td title="${escHtml(path)}">${escHtml(shortPath)}</td>
      <td>${escHtml(owasp)}</td>
      <td class="mitre-cell" title="${escHtml(mitreTxt)}">${confDot}${escHtml(mitreTxt.length > 30 ? mitreTxt.substring(0, 27) + '...' : mitreTxt)}</td>
      <td>${cvss}</td>
      <td title="${escHtml(detail)}">${escHtml(shortDetail)}</td>
    </tr>`;
  }).join('');

  // Click to open modal
  tbody.querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', () => {
      const idx = parseInt(tr.dataset.idx);
      showFindingModal(allFindings[idx]);
    });
  });
}

// ── Filtering ───────────────────────────────────────────────────
document.getElementById('filterInput').addEventListener('input', applyFilters);
document.getElementById('filterSeverity').addEventListener('change', applyFilters);

function applyFilters() {
  const text = document.getElementById('filterInput').value.toLowerCase();
  const sev = document.getElementById('filterSeverity').value;

  const filtered = allFindings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (text) {
      const searchable = JSON.stringify(f).toLowerCase();
      if (!searchable.includes(text)) return false;
    }
    return true;
  });
  renderFindings(filtered);
}

// ── Finding Modal ───────────────────────────────────────────────
function showFindingModal(f) {
  document.getElementById('modalOverlay').style.display = '';
  document.getElementById('modalTitle').textContent = (f.type || f.module || 'Finding') + ' — ' + (f.severity || 'N/A');

  // Build MITRE section with full details
  let mitreHtml = '-';
  if (f.mitre_attack && f.mitre_attack.length > 0) {
    mitreHtml = f.mitre_attack.map(mt => {
      const confClass = 'conf-' + (mt.confidence || 'medium');
      const mitigations = (mt.mitigations || []).map(m => `<li>${escHtml(m)}</li>`).join('');
      const platforms = (mt.platforms || []).join(', ');
      const killChain = (mt.kill_chain || []).join(' → ');
      return `<div class="modal-mitre-card">
        <div class="modal-mitre-header">
          <a href="${escHtml(mt.url)}" target="_blank" rel="noopener" class="mitre-link">${escHtml(mt.technique)} — ${escHtml(mt.name)}</a>
          <span class="conf-badge ${confClass}">${escHtml(mt.confidence || 'medium')}</span>
        </div>
        <div class="modal-mitre-tactic">${escHtml(mt.tactic)}</div>
        ${mt.detection ? `<div class="modal-mitre-section"><strong>Detection:</strong> ${escHtml(mt.detection)}</div>` : ''}
        ${mitigations ? `<div class="modal-mitre-section"><strong>Mitigations:</strong><ul>${mitigations}</ul></div>` : ''}
        ${platforms ? `<div class="modal-mitre-meta"><span>Platforms:</span> ${escHtml(platforms)}</div>` : ''}
        ${killChain ? `<div class="modal-mitre-meta"><span>Kill Chain:</span> ${escHtml(killChain)}</div>` : ''}
      </div>`;
    }).join('');
  }

  const fields = [
    ['Severity', `<span class="sev-badge sev-${f.severity || 'None'}">${f.severity || 'None'}</span>  CVSS: ${f.cvss_score != null ? f.cvss_score.toFixed(1) : '-'}  Vector: ${f.cvss_vector || '-'}`],
    ['OWASP Category', f.owasp_category || '-'],
    ['MITRE ATT&CK', mitreHtml],
    ['Kill Chain', (f.mitre_kill_chain || []).join(' → ') || '-'],
    ['URL / Path', f.url || f.path || '-'],
    ['Parameter', f.parameter || f.param || '-'],
    ['Detail', f.detail || f.issue || '-'],
    ['Payload', f.payload ? `<pre>${escHtml(f.payload)}</pre>` : '-'],
    ['Evidence', f.evidence || '-'],
    ['Recommendation', f.recommendation || '-'],
  ];

  let html = fields.map(([label, val]) =>
    `<div class="modal-field">
      <div class="mf-label">${label}</div>
      <div class="mf-value">${val}</div>
    </div>`
  ).join('');

  // Screenshot evidence
  if (f.screenshot) {
    const filename = f.screenshot.split('/').pop().split('\\').pop();
    html += `<div class="modal-evidence">
      <div class="mf-label">Screenshot</div>
      <img src="/api/evidence/${encodeURIComponent(filename)}" alt="Evidence screenshot" />
    </div>`;
  }

  document.getElementById('modalContent').innerHTML = html;
}

document.getElementById('modalClose').addEventListener('click', () => {
  document.getElementById('modalOverlay').style.display = 'none';
});
document.getElementById('modalOverlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) {
    document.getElementById('modalOverlay').style.display = 'none';
  }
});

// ── History ─────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch(API + '/api/scans');
    const scans = await res.json();
    const tbody = document.getElementById('historyBody');

    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-dim)">No scans yet</td></tr>';
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const shortId = s.scan_id.substring(0, 8);
      const actions = [`<button class="btn-sm" onclick="viewScan('${s.scan_id}')">View</button>`];
      if (s.status === 'running') {
        actions.push(`<button class="btn-sm btn-danger" onclick="cancelScan('${s.scan_id}')">Cancel</button>`);
      }
      actions.push(`<button class="btn-sm btn-danger" onclick="deleteScan('${s.scan_id}')">Delete</button>`);
      return `<tr>
        <td><code>${shortId}</code></td>
        <td>${escHtml(s.target)}</td>
        <td>${s.mode}</td>
        <td><span class="status-badge status-${s.status}">${s.status}</span></td>
        <td>${s.findings_count}</td>
        <td>${s.started_at}</td>
        <td>${actions.join(' ')}</td>
      </tr>`;
    }).join('');
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

async function viewScan(scanId) {
  try {
    const res = await fetch(API + '/api/scan/' + scanId);
    const data = await res.json();

    // Switch to scan tab and show results
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="scan"]').classList.add('active');
    document.getElementById('panel-scan').classList.add('active');

    document.getElementById('progressCard').style.display = '';
    document.getElementById('progressStage').textContent = data.current_stage;
    document.getElementById('progressPct').textContent = data.progress + '%';
    document.getElementById('progressFill').style.width = data.progress + '%';
    document.getElementById('elapsed').textContent = data.elapsed + 's';
    document.getElementById('findingsCount').textContent = data.findings_count || 0;

    // Show stage chips
    const timeline = document.getElementById('stageTimeline');
    timeline.innerHTML = (data.stages || []).map(s =>
      `<span class="stage-chip done">${s.name} (${s.time}s)</span>`
    ).join('');

    // Show results if any findings exist (even for running/failed scans)
    if (data.findings && data.findings.length > 0) {
      showResults(data);
    } else if (data.status === 'running') {
      // Still running — start polling
      activeScanId = scanId;
      startPolling();
    }
  } catch (err) {
    alert('Failed to load scan: ' + err.message);
  }
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan?')) return;
  try {
    await fetch(API + '/api/scan/' + scanId, { method: 'DELETE' });
    loadHistory();
  } catch (err) {
    alert('Failed to delete: ' + err.message);
  }
}

async function cancelScan(scanId) {
  if (!confirm('Cancel this running scan?')) return;
  try {
    await fetch(API + '/api/scan/' + scanId + '/cancel', { method: 'POST' });
    loadHistory();
  } catch (err) {
    alert('Failed to cancel: ' + err.message);
  }
}

// ── OWASP Reference ────────────────────────────────────────────
async function loadOwaspRef() {
  try {
    const res = await fetch(API + '/api/owasp');
    const map = await res.json();
    const container = document.getElementById('owaspReference');

    container.innerHTML = Object.entries(map).map(([id, name]) =>
      `<div class="owasp-ref-card">
        <span class="owasp-id">${escHtml(id)}</span>
        <span class="owasp-name">${escHtml(name)}</span>
      </div>`
    ).join('');
  } catch (err) {
    console.error('Failed to load OWASP data:', err);
  }
}

// ── MITRE ATT&CK Breakdown Renderer ────────────────────────────
async function renderMitreBreakdown(findings, scanData) {
  // 1. Matrix coverage heatmap (fetched from API for accurate tactic data)
  try {
    const mitreRes = await fetch(API + '/api/scan/' + (scanData.scan_id || activeScanId) + '/mitre');
    const mitreData = await mitreRes.json();
    const coverage = mitreData.matrix_coverage || {};
    const tactics = coverage.tactics || [];

    // Render matrix strip heatmap
    const stripEl = document.getElementById('mitreMatrixCoverage');
    if (stripEl && tactics.length) {
      stripEl.innerHTML = `<div class="matrix-summary">
        <span class="matrix-stat">${coverage.tactics_with_hits || 0}/${coverage.total_tactics || 14} tactics</span>
        <span class="matrix-stat">${coverage.total_technique_hits || 0}/${coverage.total_techniques_in_db || 0} techniques</span>
        <span class="matrix-stat">${coverage.overall_coverage_pct || 0}% coverage</span>
      </div>` +
      '<div class="matrix-heatmap">' + tactics.map(t => {
        const heat = t.coverage_pct > 50 ? 'heat-high' : t.coverage_pct > 0 ? 'heat-med' : 'heat-none';
        return `<div class="matrix-cell ${heat}" title="${escHtml(t.tactic)} (${t.tactic_id}): ${t.detected_techniques}/${t.total_techniques} techniques — ${t.coverage_pct}%">
          <div class="mc-name">${escHtml(t.tactic)}</div>
          <div class="mc-id">${escHtml(t.tactic_id)}</div>
          <div class="mc-stat">${t.detected_techniques}/${t.total_techniques}</div>
        </div>`;
      }).join('') + '</div>';
    }

    // 2. Technique breakdown bars (grouped by tactic, sorted by ATT&CK order)
    const breakdown = mitreData.mitre_breakdown || [];
    let techHtml = '';
    for (const tacGroup of breakdown) {
      techHtml += `<div class="mitre-tactic-section">
        <div class="mitre-tactic-bar-header">
          <span class="tactic-name">${escHtml(tacGroup.tactic)}</span>
          <span class="tactic-meta">${escHtml(tacGroup.tactic_id)} &middot; ${tacGroup.technique_count} technique${tacGroup.technique_count !== 1 ? 's' : ''}</span>
        </div>`;
      const maxCount = Math.max(...tacGroup.techniques.map(t => t.finding_count), 1);
      for (const tech of tacGroup.techniques) {
        const pct = (tech.finding_count / maxCount) * 100;
        const confClass = 'conf-' + (tech.confidence || 'medium');
        techHtml += `<div class="mitre-row">
          <span class="label"><a href="${escHtml(tech.url)}" target="_blank" rel="noopener">${escHtml(tech.technique_id)} — ${escHtml(tech.name)}</a></span>
          <span class="conf-dot ${confClass}" title="${tech.confidence || 'medium'} confidence"></span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--high)"></div></div>
          <span class="count">${tech.finding_count}</span>
        </div>`;
      }
      techHtml += '</div>';
    }
    document.getElementById('mitreBreakdown').innerHTML = techHtml || '<span style="color:var(--text-dim)">No MITRE ATT&amp;CK mappings</span>';

    // 3. Attack paths
    const paths = mitreData.attack_paths || [];
    const pathEl = document.getElementById('attackPaths');
    if (pathEl && paths.length) {
      const kcColors = {
        'Reconnaissance': '#5c6bc0',
        'Weaponization': '#7e57c2',
        'Delivery': '#ab47bc',
        'Exploitation': '#ef5350',
        'Installation': '#ff7043',
        'Command & Control': '#ffa726',
        'Actions on Objectives': '#66bb6a',
      };
      pathEl.innerHTML = '<div class="attack-path-chain">' + paths.map((p, idx) => {
        const color = kcColors[p.phase] || 'var(--accent)';
        const connector = idx < paths.length - 1 ? '<div class="path-connector"></div>' : '';
        const titles = p.findings.map(f => escHtml(f.title)).slice(0, 4).join('<br>');
        const extra = p.finding_count > 4 ? `<br><span class="path-more">+${p.finding_count - 4} more</span>` : '';
        return `<div class="path-node" style="--node-color:${color}">
          <div class="path-phase">${escHtml(p.phase)}</div>
          <div class="path-count">${p.finding_count} finding${p.finding_count !== 1 ? 's' : ''}</div>
          <div class="path-findings">${titles}${extra}</div>
        </div>${connector}`;
      }).join('') + '</div>';
    } else if (pathEl) {
      pathEl.innerHTML = '<span style="color:var(--text-dim)">No attack path data available</span>';
    }
  } catch (err) {
    console.error('Failed to load MITRE breakdown:', err);
  }
}

// ── MITRE ATT&CK Reference Panel ──────────────────────────────
async function loadMitreRef() {
  try {
    // Load tactics and techniques in parallel
    const [tacRes, techRes] = await Promise.all([
      fetch(API + '/api/mitre/tactics'),
      fetch(API + '/api/mitre'),
    ]);
    const tactics = await tacRes.json();
    const techniques = await techRes.json();

    document.getElementById('mitreTechCount').textContent = Object.keys(techniques).length;

    // Tactic overview cards
    const overviewEl = document.getElementById('mitreTacticOverview');
    if (overviewEl) {
      overviewEl.innerHTML = tactics.map(tac => {
        const techCount = Object.values(techniques).filter(t => t.tactic_id === tac.id || (t.tactics || []).some(tt => tt.id === tac.id)).length;
        return `<a href="${escHtml(tac.url)}" target="_blank" rel="noopener" class="tactic-overview-card">
          <div class="toc-id">${escHtml(tac.id)}</div>
          <div class="toc-name">${escHtml(tac.name)}</div>
          <div class="toc-count">${techCount} technique${techCount !== 1 ? 's' : ''}</div>
          <div class="toc-desc">${escHtml(tac.description)}</div>
        </a>`;
      }).join('');
    }

    // Group techniques by tactic
    const container = document.getElementById('mitreReference');
    const byTactic = {};
    for (const [tid, info] of Object.entries(techniques)) {
      const allTactics = info.tactics || [{ id: info.tactic_id, name: info.tactic }];
      for (const tac of allTactics) {
        if (!byTactic[tac.name]) byTactic[tac.name] = { id: tac.id, techs: [] };
        byTactic[tac.name].techs.push({ id: tid, ...info });
      }
    }

    // Sort tactics by ATT&CK ordinal
    const tacticOrder = {};
    tactics.forEach(t => { tacticOrder[t.name] = t.ordinal; });

    let html = '';
    for (const tactic of Object.keys(byTactic).sort((a, b) => (tacticOrder[a] || 99) - (tacticOrder[b] || 99))) {
      const group = byTactic[tactic];
      html += `<div class="mitre-tactic-group">
        <h3 class="mitre-tactic-header">
          ${escHtml(tactic)}
          <span class="mitre-tactic-id">${escHtml(group.id)}</span>
          <span class="mitre-tactic-count">${group.techs.length}</span>
        </h3>
        <div class="mitre-technique-list">`;

      for (const t of group.techs.sort((a, b) => a.id.localeCompare(b.id))) {
        const platforms = (t.platforms || []).join(', ');
        const dataSources = (t.data_sources || []).join(', ');
        const mitigations = (t.mitigations || []).map(m => `<li>${escHtml(m)}</li>`).join('');
        const killChain = (t.kill_chain || []).join(' → ');
        const subBadge = t.is_subtechnique ? '<span class="sub-technique-badge">SUB</span>' : '';
        const weightClass = t.severity_weight >= 8 ? 'weight-high' : t.severity_weight >= 5 ? 'weight-med' : 'weight-low';

        html += `<div class="mitre-ref-card-v2" onclick="this.classList.toggle('expanded')">
          <div class="mrc-header">
            <span class="mitre-tid">${escHtml(t.id)}</span>
            ${subBadge}
            <span class="mitre-tname">${escHtml(t.name)}</span>
            <span class="weight-badge ${weightClass}">${t.severity_weight.toFixed(1)}</span>
            <a href="${escHtml(t.url)}" target="_blank" rel="noopener" class="mrc-link" onclick="event.stopPropagation()">&#x2197;</a>
          </div>
          <div class="mrc-desc">${escHtml(t.description)}</div>
          <div class="mrc-details">
            ${t.detection ? `<div class="mrc-section"><div class="mrc-label">DETECTION</div><div class="mrc-text">${escHtml(t.detection)}</div></div>` : ''}
            ${mitigations ? `<div class="mrc-section"><div class="mrc-label">MITIGATIONS</div><ul class="mrc-list">${mitigations}</ul></div>` : ''}
            ${platforms ? `<div class="mrc-section"><div class="mrc-label">PLATFORMS</div><div class="mrc-tags">${(t.platforms || []).map(p => `<span class="mrc-tag">${escHtml(p)}</span>`).join('')}</div></div>` : ''}
            ${dataSources ? `<div class="mrc-section"><div class="mrc-label">DATA SOURCES</div><div class="mrc-text">${escHtml(dataSources)}</div></div>` : ''}
            ${killChain ? `<div class="mrc-section"><div class="mrc-label">KILL CHAIN</div><div class="mrc-text">${escHtml(killChain)}</div></div>` : ''}
          </div>
        </div>`;
      }

      html += `</div></div>`;
    }
    container.innerHTML = html;
  } catch (err) {
    console.error('Failed to load MITRE data:', err);
  }
}

// ── Download Functions ──────────────────────────────────────────
function downloadJSON() {
  if (!allFindings.length) return;
  const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: 'application/json' });
  _downloadBlob(blob, 'scan_results.json');
}

function downloadCSV() {
  if (!allFindings.length) return;
  const headers = ['Severity', 'Type', 'URL', 'OWASP Category', 'MITRE ATT&CK', 'CVSS Score', 'CVSS Vector', 'Parameter', 'Detail', 'Payload', 'Evidence', 'Recommendation'];
  const rows = allFindings.map(f => [
    f.severity || '',
    f.type || f.module || '',
    f.url || f.path || '',
    f.owasp_category || '',
    (f.mitre_attack || []).map(mt => mt.technique + ' ' + mt.name).join('; '),
    f.cvss_score != null ? f.cvss_score : '',
    f.cvss_vector || '',
    f.parameter || f.param || '',
    f.detail || f.issue || '',
    f.payload || '',
    f.evidence || '',
    f.recommendation || '',
  ]);
  const csvContent = [headers, ...rows]
    .map(row => row.map(cell => '"' + String(cell).replace(/"/g, '""') + '"').join(','))
    .join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv' });
  _downloadBlob(blob, 'scan_results.csv');
}

function downloadTXT() {
  if (!allFindings.length) return;
  const divider = '='.repeat(70);
  const lines = ['VULNERABILITY SCAN RESULTS', divider, 'Total findings: ' + allFindings.length, ''];
  allFindings.forEach((f, i) => {
    lines.push('-'.repeat(70));
    lines.push('Finding #' + (i + 1));
    lines.push('-'.repeat(70));
    lines.push('Severity      : ' + (f.severity || 'N/A'));
    lines.push('Type          : ' + (f.type || f.module || 'N/A'));
    lines.push('URL           : ' + (f.url || f.path || 'N/A'));
    lines.push('OWASP         : ' + (f.owasp_category || 'N/A'));
    lines.push('MITRE ATT&CK  : ' + ((f.mitre_attack || []).map(mt => mt.technique + ' — ' + mt.name).join(', ') || 'N/A'));
    lines.push('CVSS Score    : ' + (f.cvss_score != null ? f.cvss_score : 'N/A'));
    lines.push('CVSS Vector   : ' + (f.cvss_vector || 'N/A'));
    lines.push('Parameter     : ' + (f.parameter || f.param || 'N/A'));
    lines.push('Detail        : ' + (f.detail || f.issue || 'N/A'));
    lines.push('Payload       : ' + (f.payload || 'N/A'));
    lines.push('Evidence      : ' + (f.evidence || 'N/A'));
    lines.push('Recommendation: ' + (f.recommendation || 'N/A'));
    lines.push('');
  });
  lines.push(divider);
  lines.push('Report generated: ' + new Date().toISOString());
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  _downloadBlob(blob, 'scan_results.txt');
}

function _downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Utility ─────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}
