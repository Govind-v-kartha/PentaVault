/* PentaVault SOC Obsidian Frontend */

const API = '';
const MAX_THREADS = 10;
const VIRTUAL_FINDING_CHUNK = 80;
const HAS_THREE = typeof window.THREE !== 'undefined';
const HAS_D3 = typeof window.d3 !== 'undefined';
const REDUCED_MOTION = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

let activeScanId = null;
let pollTimer = null;
let scanTimerInterval = null;
let scanStartTime = null;
let allFindings = [];
let filteredFindings = [];
let currentModalFindingIdx = null;
let findingIndexLookup = new Map();
let seenFindings = 0;
let seenStageCount = 0;
let activeOwaspFilter = '';

let virtualCursor = 0;
let virtualSource = [];

let mitreBreakdownReqToken = 0;
let mitreRefReqToken = 0;
let owaspRefReqToken = 0;

let _mitreAiTechId = '';
let _mitreAiTechName = '';
let _mitreAiTactic = '';

const mappingCache = {
  owaspReference: null,
  mitreReference: null,
  mitreByScan: {},
};

let mitreBreakdownState = {
  breakdown: [],
  coverageTactics: [],
  selectedTactic: '',
  selectedConfidence: '',
  search: '',
  scanCacheKey: '',
};

const sceneRuntimes = [];
let renderLoopStarted = false;
let resizeBound = false;
let stageAudioCtx = null;

const sceneControllers = {
  globe: null,
  progress: null,
  attackGraph: null,
  mitreMini: null,
  mitreFull: null,
};

document.addEventListener('DOMContentLoaded', () => {
  bindTabs();
  bindModeCards();
  bindScanForm();
  bindFindingsFilters();
  bindFindingViewportVirtualization();
  bindModalHandlers();
  bindMitreControls();
  bindMitreRefControls();
  bindMiscControls();
  bindLiveFindingStreamBehavior();
  initClock();
  initVisualScenes();
  bindTargetPreview();
  resetScanForm();
  appendTerminalLine('Awaiting mission launch sequence');
});

function bindTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const panel = document.getElementById('panel-' + btn.dataset.tab);
      if (panel) panel.classList.add('active');

      if (btn.dataset.tab === 'scan') {
        const resultsVisible = document.getElementById('resultsPanel')?.style.display !== 'none';
        const progressVisible = document.getElementById('progressCard')?.style.display !== 'none';
        const hasResultsContext = resultsVisible || allFindings.length > 0;
        if (!activeScanId && !pollTimer && !hasResultsContext && !progressVisible) {
          resetScanForm();
        }
      }
      if (btn.dataset.tab === 'history') loadHistory();
      if (btn.dataset.tab === 'owasp') loadOwaspRef();
      if (btn.dataset.tab === 'mitre') {
        loadMitreRef();
        syncMitreFullScene();
      }
    });
  });
}

function bindModeCards() {
  const modeSelect = document.getElementById('mode');
  if (!modeSelect) return;
  document.querySelectorAll('.mode-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      modeSelect.value = card.dataset.mode;
      const chip = document.getElementById('headerModeChip');
      if (chip && !pollTimer) chip.textContent = `Mode: ${String(card.dataset.mode || '').toUpperCase()}`;
    });
  });
}

function bindScanForm() {
  const form = document.getElementById('scanForm');
  if (!form) return;
  form.addEventListener('submit', startScanFromForm);

  const browserToggle = document.getElementById('useBrowser');
  browserToggle?.addEventListener('change', async () => {
    if (!activeScanId) return;
    try {
      await fetch(API + '/api/scan/' + activeScanId, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ use_browser: browserToggle.checked }),
      });
    } catch (err) {
      console.error('Failed to toggle browser setting:', err);
    }
  });
}

function bindFindingsFilters() {
  document.getElementById('filterInput')?.addEventListener('input', applyFilters);
  document.getElementById('filterSeverity')?.addEventListener('change', applyFilters);
}

function bindFindingViewportVirtualization() {
  const viewport = document.getElementById('findingsViewport');
  if (!viewport) return;
  viewport.addEventListener('scroll', () => {
    if (viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - 120) {
      appendFindingsChunk();
    }
  });
}

function bindModalHandlers() {
  document.getElementById('modalClose')?.addEventListener('click', () => {
    document.getElementById('modalOverlay').style.display = 'none';
  });
  document.getElementById('modalOverlay')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
      document.getElementById('modalOverlay').style.display = 'none';
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.getElementById('mitreAiOverlay').style.display !== 'none') {
      closeMitreAiPanel();
    }
  });

  document.addEventListener('click', (e) => {
    if (e.target.id === 'mitreAiOverlay') {
      closeMitreAiPanel();
    }
  });
}

function bindMitreControls() {
  const tactic = document.getElementById('mitreFilterTactic');
  const confidence = document.getElementById('mitreFilterConfidence');
  const search = document.getElementById('mitreFilterSearch');
  const clear = document.getElementById('mitreFilterClear');

  if (!tactic || !confidence || !search || !clear) return;

  tactic.addEventListener('change', () => {
    mitreBreakdownState.selectedTactic = tactic.value;
    _highlightMatrixFilter(mitreBreakdownState.selectedTactic);
    _applyMitreBreakdownFilters();
  });

  confidence.addEventListener('change', () => {
    mitreBreakdownState.selectedConfidence = confidence.value;
    _applyMitreBreakdownFilters();
  });

  search.addEventListener('input', () => {
    mitreBreakdownState.search = search.value.trim().toLowerCase();
    _applyMitreBreakdownFilters();
  });

  clear.addEventListener('click', () => {
    mitreBreakdownState.selectedTactic = '';
    mitreBreakdownState.selectedConfidence = '';
    mitreBreakdownState.search = '';
    tactic.value = '';
    confidence.value = '';
    search.value = '';
    _highlightMatrixFilter('');
    _applyMitreBreakdownFilters();
    _setMappingFeedback('mitreFeedback', null, '');
  });
}

function bindMitreRefControls() {
  const search = document.getElementById('mitreRefSearch');
  const expandAll = document.getElementById('mitreRefExpandAll');
  const collapseAll = document.getElementById('mitreRefCollapseAll');

  if (!search || !expandAll || !collapseAll) return;

  search.addEventListener('input', () => _filterMitreReference(search.value));
  expandAll.addEventListener('click', () => {
    document.querySelectorAll('.mitre-ref-card-v2:not(.mitre-hidden)').forEach(card => card.classList.add('expanded'));
  });
  collapseAll.addEventListener('click', () => {
    document.querySelectorAll('.mitre-ref-card-v2').forEach(card => card.classList.remove('expanded'));
  });
}

function bindMiscControls() {
  const fsBtn = document.getElementById('btnGraphFullscreen');
  fsBtn?.addEventListener('click', async () => {
    const host = document.getElementById('attackGraphScene');
    if (!host) return;
    try {
      if (!document.fullscreenElement) {
        await host.requestFullscreen();
      } else {
        await document.exitFullscreen();
      }
    } catch (err) {
      console.error('Fullscreen request failed:', err);
    }
  });

  const mitreAskInput = document.getElementById('mitreAiQuestion');
  mitreAskInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      askMitreAiFollowup();
    }
  });
}

function bindLiveFindingStreamBehavior() {
  const stream = document.getElementById('findingStream');
  if (!stream) return;
  stream.addEventListener('scroll', () => {
    const nearBottom = stream.scrollTop + stream.clientHeight >= stream.scrollHeight - 10;
    stream.dataset.paused = nearBottom ? '0' : '1';
  });
}

function bindTargetPreview() {
  const input = document.getElementById('target');
  if (!input) return;
  let timer = null;
  input.addEventListener('input', () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      const preview = estimateTargetSignal(input.value.trim());
      const readout = document.getElementById('geoReadout');
      if (readout) readout.textContent = preview.label;
      sceneControllers.globe?.setTarget(preview.lat, preview.lng, preview.label);
    }, 180);
  });
}

function initClock() {
  const clockEl = document.getElementById('headerClock');
  if (!clockEl) return;
  const paint = () => {
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };
  paint();
  setInterval(paint, 1000);
}

function setFormDisabled(disabled) {
  ['target', 'crawlMode', 'threads', 'timeout', 'requestDelay', 'cookie'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = disabled;
  });
  document.querySelectorAll('.mode-card').forEach(card => {
    card.disabled = disabled;
    card.style.pointerEvents = disabled ? 'none' : '';
    card.style.opacity = disabled ? '0.6' : '1';
  });
}

function resetScanForm() {
  const target = document.getElementById('target');
  if (target) target.value = '';

  const modeSel = document.getElementById('mode');
  if (modeSel) modeSel.value = 'quick';
  document.querySelectorAll('.mode-card').forEach(card => card.classList.toggle('active', card.dataset.mode === 'quick'));

  const threads = document.getElementById('threads');
  const timeout = document.getElementById('timeout');
  const delay = document.getElementById('requestDelay');
  const cookie = document.getElementById('cookie');
  const crawlMode = document.getElementById('crawlMode');
  const useBrowser = document.getElementById('useBrowser');

  if (threads) threads.value = '5';
  if (timeout) timeout.value = '10';
  if (delay) delay.value = '0';
  if (cookie) cookie.value = '';
  if (crawlMode) crawlMode.value = 'auto';
  if (useBrowser) useBrowser.checked = false;

  setFormDisabled(false);
  const btn = document.getElementById('btnStart');
  if (btn) {
    btn.disabled = false;
    btn.textContent = 'Start Scan';
  }
  const cancel = document.getElementById('btnCancel');
  if (cancel) cancel.style.display = 'none';

  const progress = document.getElementById('progressCard');
  const results = document.getElementById('resultsPanel');
  const totalTime = document.getElementById('totalTimeDisplay');
  if (progress) progress.style.display = 'none';
  if (results) results.style.display = 'none';
  if (totalTime) totalTime.style.display = 'none';

  setHeaderModeChip('Idle');
  setRailScanning(false);
  _renderRuntimeBehavior(null);
  clearFindingStream();
  clearMissionTerminal();

  activeOwaspFilter = '';
  seenFindings = 0;
  seenStageCount = 0;

  const readout = document.getElementById('geoReadout');
  if (readout) readout.textContent = 'Awaiting target intelligence...';

  sceneControllers.progress?.setProgress(0);
  sceneControllers.progress?.pulseStage();
}

function setHeaderModeChip(text) {
  const chip = document.getElementById('headerModeChip');
  if (!chip) return;
  chip.textContent = text;
}

function setRailScanning(on) {
  const node = document.getElementById('railLive');
  if (!node) return;
  node.classList.toggle('scanning', !!on);
}

async function startScanFromForm(e) {
  e.preventDefault();

  const targetRaw = document.getElementById('target').value.trim();
  if (!targetRaw) return;

  let threads = parseInt(document.getElementById('threads').value || '5', 10);
  if (!Number.isFinite(threads) || threads < 1) threads = 1;
  if (threads > MAX_THREADS) {
    threads = MAX_THREADS;
    document.getElementById('threads').value = String(MAX_THREADS);
    alert(`Thread limit capped to ${MAX_THREADS} for stability.`);
  }

  const body = {
    target: targetRaw,
    mode: document.getElementById('mode').value,
    threads,
    timeout: parseFloat(document.getElementById('timeout').value || '10'),
    request_delay: parseFloat(document.getElementById('requestDelay').value || '0') || 0,
    cookie: document.getElementById('cookie').value.trim() || null,
    use_browser: document.getElementById('useBrowser').checked,
    crawl_mode: document.getElementById('crawlMode').value,
  };

  const preview = estimateTargetSignal(targetRaw);
  sceneControllers.globe?.setTarget(preview.lat, preview.lng, preview.label);
  const readout = document.getElementById('geoReadout');
  if (readout) readout.textContent = preview.label;

  const btn = document.getElementById('btnStart');
  const cancelBtn = document.getElementById('btnCancel');
  btn.disabled = true;
  btn.textContent = 'Launching…';
  setFormDisabled(true);

  cancelBtn.style.display = 'inline-flex';
  cancelBtn.disabled = false;

  document.getElementById('progressCard').style.display = '';
  document.getElementById('resultsPanel').style.display = 'none';
  document.getElementById('progressStage').textContent = 'Initialising…';
  document.getElementById('progressPct').textContent = '0%';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('elapsed').textContent = '0s';
  document.getElementById('findingsCount').textContent = '0';
  document.getElementById('stageTimeline').innerHTML = '';
  document.getElementById('totalTimeDisplay').style.display = 'none';

  clearMissionTerminal();
  clearFindingStream();
  appendTerminalLine('Boot sequence accepted');

  seenFindings = 0;
  seenStageCount = 0;

  startScanTimer();
  setHeaderModeChip('Running');
  setRailScanning(true);

  sceneControllers.progress?.setProgress(0);
  sceneControllers.progress?.pulseStage();

  try {
    const res = await fetch(API + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const detail = err.detail;
      if (detail && typeof detail === 'object') {
        const errors = Array.isArray(detail.errors) ? detail.errors : [];
        const warnings = Array.isArray(detail.warnings) ? detail.warnings : [];
        throw new Error([...errors, ...warnings].join('\n') || ('Server returned ' + res.status));
      }
      throw new Error(detail || 'Server returned ' + res.status);
    }

    const data = await res.json();
    activeScanId = data.scan_id;
    startPolling();
  } catch (err) {
    alert('Failed to start scan: ' + err.message);
    stopScanTimer();
    setHeaderModeChip('Idle');
    setRailScanning(false);
    btn.disabled = false;
    btn.textContent = 'Start Scan';
    setFormDisabled(false);
    cancelBtn.style.display = 'none';
  }
}

function startScanTimer() {
  scanStartTime = Date.now();
  if (scanTimerInterval) clearInterval(scanTimerInterval);
  scanTimerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    const el = document.getElementById('elapsed');
    if (el) el.textContent = formatDuration(elapsed);
  }, 250);
}

function stopScanTimer() {
  if (scanTimerInterval) {
    clearInterval(scanTimerInterval);
    scanTimerInterval = null;
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollScan, 1000);
}

async function pollScan() {
  if (!activeScanId) return;
  try {
    const res = await fetch(API + '/api/scan/' + activeScanId);
    if (!res.ok) throw new Error('Scan status fetch failed');
    const data = await res.json();

    document.getElementById('progressStage').textContent = data.current_stage || 'Working';
    document.getElementById('progressPct').textContent = `${data.progress || 0}%`;
    document.getElementById('progressFill').style.width = `${data.progress || 0}%`;
    document.getElementById('elapsed').textContent = formatDuration(Number(data.elapsed || 0));
    document.getElementById('findingsCount').textContent = data.findings_count || 0;

    renderStageTimeline(data.stages || []);
    syncMissionTerminal(data);
    syncLiveFindingStream(data.findings || []);
    _renderRuntimeBehavior(data);

    sceneControllers.progress?.setProgress(Number(data.progress || 0));

    if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
      clearInterval(pollTimer);
      pollTimer = null;
      stopScanTimer();

      const elapsed = scanStartTime ? Math.floor((Date.now() - scanStartTime) / 1000) : Math.round(Number(data.elapsed || 0));
      const elapsedText = formatDuration(elapsed);
      document.getElementById('elapsed').textContent = elapsedText;

      const totalTimeEl = document.getElementById('totalTimeDisplay');
      const statusLabel = data.status === 'completed' ? 'Mission complete' : (data.status === 'cancelled' ? 'Mission aborted' : 'Mission failed');
      totalTimeEl.innerHTML = `<span class="total-time-icon">⏱</span> ${statusLabel} in <strong>${elapsedText}</strong>`;
      totalTimeEl.className = 'total-time-display status-' + data.status;
      totalTimeEl.style.display = '';

      const startBtn = document.getElementById('btnStart');
      const cancelBtn = document.getElementById('btnCancel');
      startBtn.disabled = false;
      startBtn.textContent = 'Start Scan';
      setFormDisabled(false);
      cancelBtn.style.display = 'none';

      setRailScanning(false);
      setHeaderModeChip(data.status === 'completed' ? 'Completed' : data.status === 'cancelled' ? 'Cancelled' : 'Failed');

      if (data.status === 'completed' || (Array.isArray(data.findings) && data.findings.length > 0)) {
        showResults(data);
      }
    }
  } catch (err) {
    console.error('Polling error:', err);
    clearInterval(pollTimer);
    pollTimer = null;
    stopScanTimer();

    const startBtn = document.getElementById('btnStart');
    const cancelBtn = document.getElementById('btnCancel');
    startBtn.disabled = false;
    startBtn.textContent = 'Start Scan';
    cancelBtn.style.display = 'none';
    setFormDisabled(false);

    setHeaderModeChip('Disconnected');
    setRailScanning(false);
  }
}

function renderStageTimeline(stages) {
  const el = document.getElementById('stageTimeline');
  if (!el) return;
  el.innerHTML = stages.map(stage => `<span class="stage-chip done">${escHtml(stage.name)} (${stage.time}s)</span>`).join('');
}

function syncMissionTerminal(scanData) {
  const stages = Array.isArray(scanData.stages) ? scanData.stages : [];
  if (stages.length > seenStageCount) {
    for (let i = seenStageCount; i < stages.length; i++) {
      const stage = stages[i];
      appendTerminalLine(`${stage.name} completed in ${stage.time}s`);
      sceneControllers.progress?.pulseStage();
      maybePlayCheckpointTone();
    }
    seenStageCount = stages.length;
  }
}

function syncLiveFindingStream(findings) {
  if (!Array.isArray(findings)) return;
  if (findings.length <= seenFindings) return;
  for (let i = seenFindings; i < findings.length; i++) {
    pushFindingStreamItem(findings[i]);
  }
  seenFindings = findings.length;
}

function appendTerminalLine(text) {
  const terminal = document.getElementById('missionTerminal');
  if (!terminal) return;
  const line = document.createElement('div');
  line.className = 'terminal-line';
  terminal.appendChild(line);

  const rendered = String(text || '');
  if (REDUCED_MOTION) {
    line.textContent = rendered;
  } else {
    let idx = 0;
    const tick = () => {
      idx += 1;
      line.textContent = rendered.slice(0, idx);
      if (idx < rendered.length) {
        requestAnimationFrame(tick);
      }
    };
    tick();
  }
  terminal.scrollTop = terminal.scrollHeight;
}

function clearMissionTerminal() {
  const terminal = document.getElementById('missionTerminal');
  if (terminal) terminal.innerHTML = '';
}

function pushFindingStreamItem(finding) {
  const stream = document.getElementById('findingStream');
  if (!stream) return;

  const sev = String(finding?.severity || 'None').toLowerCase();
  const item = document.createElement('div');
  item.className = `stream-item sev-${sev}`;
  item.innerHTML = `<div><strong>${escHtml(finding?.severity || 'None')}</strong> · ${escHtml(finding?.type || finding?.module || 'Finding')}</div>`
    + `<div>${escHtml((finding?.detail || finding?.payload || '').slice(0, 110))}</div>`;
  stream.appendChild(item);

  const paused = stream.dataset.paused === '1';
  if (!paused) {
    stream.scrollTop = stream.scrollHeight;
  }
}

function clearFindingStream() {
  const stream = document.getElementById('findingStream');
  if (stream) {
    stream.innerHTML = '';
    stream.dataset.paused = '0';
  }
}

function maybePlayCheckpointTone() {
  const enabled = document.getElementById('audioCueToggle')?.checked;
  if (!enabled) return;
  try {
    if (!stageAudioCtx) stageAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const now = stageAudioCtx.currentTime;
    const osc = stageAudioCtx.createOscillator();
    const gain = stageAudioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(620, now);
    osc.frequency.exponentialRampToValueAtTime(880, now + 0.2);
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.08, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.21);
    osc.connect(gain);
    gain.connect(stageAudioCtx.destination);
    osc.start(now);
    osc.stop(now + 0.22);
  } catch (err) {
    console.warn('Audio cue failed:', err);
  }
}

function showResults(data) {
  const findings = Array.isArray(data.findings) ? data.findings : [];
  allFindings = findings;
  findingIndexLookup = new Map();
  allFindings.forEach((f, idx) => findingIndexLookup.set(f, idx));

  activeOwaspFilter = '';

  if (data?.scan_id) {
    activeScanId = data.scan_id;
  }

  const resultsPanel = document.getElementById('resultsPanel');
  if (resultsPanel) resultsPanel.style.display = '';
  _renderRuntimeBehavior(data);

  renderSeverityRing(findings);
  renderOwaspTreemap(findings);
  renderMitreBreakdown(findings, data);
  renderFindings(findings, true);
  renderStageTiming(data.stages || []);

  const aiAnalysis = document.getElementById('aiAnalysisCard');
  const aiExec = document.getElementById('aiExecCard');
  if (aiAnalysis) aiAnalysis.style.display = '';
  if (aiExec) aiExec.style.display = '';

  const aiAnalysisContent = document.getElementById('aiAnalysisContent');
  const aiExecContent = document.getElementById('aiExecContent');
  if (aiAnalysisContent) {
    aiAnalysisContent.innerHTML = '<p class="ai-hint">Generate AI threat analysis for this mission data.</p>';
  }
  if (aiExecContent) {
    aiExecContent.innerHTML = '<p class="ai-hint">Generate an executive summary for stakeholders.</p>';
  }

  sceneControllers.attackGraph?.setData(findings, []);

  const resultsHost = document.getElementById('resultsPanel');
  if (resultsHost) {
    resultsHost.scrollIntoView({ behavior: REDUCED_MOTION ? 'auto' : 'smooth', block: 'start' });
  }
}

function renderStageTiming(stages) {
  const container = document.getElementById('stageTiming');
  if (!container) return;
  if (!Array.isArray(stages) || !stages.length) {
    container.innerHTML = '<div class="mapping-empty">No stage timing data available.</div>';
    return;
  }

  const max = Math.max(...stages.map(s => Number(s.time || 0)), 1);
  container.innerHTML = stages.map(stage => {
    const pct = (Number(stage.time || 0) / max) * 100;
    return `<div class="timing-row">`
      + `<span class="name">${escHtml(stage.name)}</span>`
      + `<div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--signal)"></div></div>`
      + `<span class="time">${Number(stage.time || 0)}s</span>`
      + `</div>`;
  }).join('');
}

function renderSeverityRing(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
  (findings || []).forEach(f => {
    const sev = f?.severity || 'None';
    if (counts[sev] != null) counts[sev] += 1;
    else counts.None += 1;
  });

  animateCounter(document.getElementById('statCritical'), counts.Critical);
  animateCounter(document.getElementById('statHigh'), counts.High);
  animateCounter(document.getElementById('statMedium'), counts.Medium);
  animateCounter(document.getElementById('statLow'), counts.Low);
  animateCounter(document.getElementById('statInfo'), counts.None);
  document.getElementById('totalBadge').textContent = String(findings.length || 0);

  const host = document.getElementById('severityChart');
  if (!host) return;
  host.innerHTML = '';

  if (!HAS_D3) {
    host.innerHTML = '<div class="mapping-empty">Severity ring unavailable (D3 not loaded).</div>';
    return;
  }

  const rect = host.getBoundingClientRect();
  const width = Math.max(240, Math.floor(rect.width));
  const height = Math.max(200, Math.floor(rect.height));
  const radius = Math.min(width, height) / 2 - 14;
  const total = Math.max(1, findings.length || 0);

  const order = ['Critical', 'High', 'Medium', 'Low', 'None'];
  const color = {
    Critical: '#ff1f4b',
    High: '#ff6b35',
    Medium: '#f5a623',
    Low: '#00ff9d',
    None: '#4fa5ff',
  };

  const svg = d3.select(host).append('svg').attr('width', width).attr('height', height);
  const g = svg.append('g').attr('transform', `translate(${width / 2},${height / 2})`);

  order.forEach((sev, idx) => {
    const inner = 20 + idx * 16;
    const outer = inner + 10;
    const pct = counts[sev] / total;

    const track = d3.arc().innerRadius(inner).outerRadius(outer).startAngle(0).endAngle(Math.PI * 2);
    const value = d3.arc().innerRadius(inner).outerRadius(outer).startAngle(0);

    g.append('path')
      .attr('d', track)
      .attr('fill', 'rgba(139,163,192,0.14)')
      .attr('stroke', 'rgba(30,45,64,0.9)');

    const arcPath = g.append('path')
      .datum({ endAngle: 0 })
      .attr('fill', color[sev])
      .attr('opacity', 0.95);

    arcPath.transition().duration(750).attrTween('d', (d) => {
      const interp = d3.interpolate(d.endAngle, Math.PI * 2 * pct);
      return (t) => {
        d.endAngle = interp(t);
        return value({ endAngle: d.endAngle });
      };
    });
  });

  g.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '-0.2em')
    .style('font-family', 'var(--font-display)')
    .style('font-size', '20px')
    .style('fill', '#c8ddf5')
    .text(String(findings.length || 0));

  g.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '1.2em')
    .style('font-size', '11px')
    .style('fill', '#8ba3c0')
    .text('findings');
}

function renderOwaspTreemap(findings) {
  const host = document.getElementById('owaspBreakdown');
  if (!host) return;
  host.innerHTML = '';

  const grouped = {};
  const severityRank = { Critical: 5, High: 4, Medium: 3, Low: 2, None: 1, Info: 1 };

  (findings || []).forEach(f => {
    const category = f?.owasp_category || 'Unknown';
    if (!grouped[category]) grouped[category] = { category, count: 0, maxSeverity: 'None' };
    grouped[category].count += 1;
    const currentRank = severityRank[grouped[category].maxSeverity] || 1;
    const nextRank = severityRank[f?.severity] || 1;
    if (nextRank > currentRank) grouped[category].maxSeverity = f?.severity || 'None';
  });

  const entries = Object.values(grouped);
  if (!entries.length) {
    host.innerHTML = '<div class="mapping-empty">No OWASP mappings available for this mission.</div>';
    return;
  }

  if (!HAS_D3) {
    host.innerHTML = entries.map(entry => `<div class="owasp-ref-card"><span class="owasp-id">${escHtml(entry.category)}</span><span class="owasp-name">${entry.count}</span></div>`).join('');
    return;
  }

  const rect = host.getBoundingClientRect();
  const width = Math.max(250, Math.floor(rect.width));
  const height = Math.max(220, Math.floor(rect.height));

  const palette = {
    Critical: '#ff1f4b',
    High: '#ff6b35',
    Medium: '#f5a623',
    Low: '#00ff9d',
    None: '#4fa5ff',
    Info: '#4fa5ff',
  };

  const root = d3.hierarchy({ children: entries }).sum(d => d.count);
  d3.treemap().size([width, height]).padding(4)(root);

  const svg = d3.select(host).append('svg').attr('width', width).attr('height', height);
  const nodes = svg.selectAll('g').data(root.leaves()).enter().append('g')
    .attr('transform', d => `translate(${d.x0},${d.y0})`)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      const category = d.data.category;
      activeOwaspFilter = activeOwaspFilter === category ? '' : category;
      applyFilters();
      renderOwaspTreemap(allFindings);
    });

  nodes.append('rect')
    .attr('width', d => Math.max(0, d.x1 - d.x0))
    .attr('height', d => Math.max(0, d.y1 - d.y0))
    .attr('rx', 10)
    .attr('fill', d => palette[d.data.maxSeverity] || '#4fa5ff')
    .attr('fill-opacity', d => activeOwaspFilter && activeOwaspFilter === d.data.category ? 0.95 : 0.65)
    .attr('stroke', d => activeOwaspFilter && activeOwaspFilter === d.data.category ? '#d6f4ff' : 'rgba(30,45,64,0.8)')
    .attr('stroke-width', 1.2);

  nodes.append('text')
    .attr('x', 8)
    .attr('y', 16)
    .style('font-size', '10px')
    .style('fill', '#06111c')
    .style('font-family', 'var(--font-mono)')
    .text(d => d.data.category.slice(0, 18));

  nodes.append('text')
    .attr('x', 8)
    .attr('y', 32)
    .style('font-size', '11px')
    .style('font-family', 'var(--font-display)')
    .style('fill', '#06111c')
    .text(d => `${d.data.count} hit${d.data.count > 1 ? 's' : ''}`);
}

function animateCounter(el, target) {
  if (!el) return;
  if (REDUCED_MOTION) {
    el.textContent = String(target);
    return;
  }
  const start = Number(el.textContent || 0);
  const startTime = performance.now();
  const duration = 800;
  const step = (now) => {
    const t = Math.min(1, (now - startTime) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    const value = Math.round(start + (target - start) * eased);
    el.textContent = String(value);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function renderFindings(findings, reset = true) {
  const tbody = document.getElementById('findingsBody');
  if (!tbody) return;

  if (reset) {
    virtualSource = Array.isArray(findings) ? findings.slice() : [];
    virtualCursor = 0;
    tbody.innerHTML = '';
  }

  appendFindingsChunk();
}

function appendFindingsChunk() {
  const tbody = document.getElementById('findingsBody');
  if (!tbody) return;
  if (!virtualSource.length || virtualCursor >= virtualSource.length) return;

  const chunk = virtualSource.slice(virtualCursor, virtualCursor + VIRTUAL_FINDING_CHUNK);
  const rows = chunk.map(f => {
    const sev = f.severity || 'None';
    const cvss = f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : '-';
    const path = f.affected_url || f.url || f.path || '-';
    const shortPath = path.length > 62 ? '...' + path.slice(-59) : path;
    const owasp = (f.owasp_category || '').replace(/^(A\d+):?\d*\s*-?\s*/, '$1 - ').substring(0, 42);
    const detail = f.detail || f.payload || f.issue || '-';
    const shortDetail = detail.length > 70 ? detail.substring(0, 67) + '...' : detail;
    const mitreList = (f.mitre_attack || []);
    const mitreTxt = mitreList.map(mt => mt.technique).join(', ') || '-';
    const topConf = mitreList.length > 0 ? mitreList[0].confidence || 'medium' : '';
    const confDot = topConf ? `<span class="conf-dot conf-${escHtml(topConf)}" title="${escHtml(topConf)} confidence"></span>` : '';
    const idx = findingIndexLookup.get(f);

    return `<tr data-idx="${idx != null ? idx : -1}">`
      + `<td><span class="sev-badge sev-${escHtml(sev)}">${escHtml(sev)}</span></td>`
      + `<td>${escHtml(f.title || f.type || f.module || '-')}</td>`
      + `<td title="${escHtml(path)}">${escHtml(shortPath)}</td>`
      + `<td>${escHtml(owasp)}</td>`
      + `<td class="mitre-cell" title="${escHtml(mitreTxt)}">${confDot}${escHtml(mitreTxt.length > 34 ? mitreTxt.slice(0, 31) + '...' : mitreTxt)}</td>`
      + `<td>${escHtml(cvss)}</td>`
      + `<td title="${escHtml(detail)}">${escHtml(shortDetail)}</td>`
      + `</tr>`;
  }).join('');

  tbody.insertAdjacentHTML('beforeend', rows);

  tbody.querySelectorAll('tr[data-idx]').forEach(tr => {
    if (tr.dataset.bound === '1') return;
    tr.dataset.bound = '1';
    tr.addEventListener('click', () => {
      const idx = Number(tr.dataset.idx);
      if (!Number.isFinite(idx) || idx < 0 || idx >= allFindings.length) return;
      showFindingModal(allFindings[idx]);
    });
  });

  virtualCursor += chunk.length;
}

function applyFilters() {
  const text = String(document.getElementById('filterInput')?.value || '').toLowerCase();
  const sev = document.getElementById('filterSeverity')?.value || '';

  filteredFindings = allFindings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (activeOwaspFilter && (f.owasp_category || '') !== activeOwaspFilter) return false;
    if (text) {
      const haystack = JSON.stringify(f).toLowerCase();
      if (!haystack.includes(text)) return false;
    }
    return true;
  });

  renderFindings(filteredFindings, true);
}

function showFindingModal(finding) {
  const overlay = document.getElementById('modalOverlay');
  if (!overlay) return;

  overlay.style.display = '';
  currentModalFindingIdx = allFindings.indexOf(finding);

  const title = document.getElementById('modalTitle');
  if (title) title.textContent = `${finding.title || finding.type || finding.module || 'Finding'} — ${finding.severity || 'N/A'}`;

  renderCvssGauge(Number(finding.cvss_score || 0), String(finding.cvss_vector || ''));

  let mitreHtml = '-';
  if (Array.isArray(finding.mitre_attack) && finding.mitre_attack.length) {
    mitreHtml = finding.mitre_attack.map(mt => {
      const conf = _normalizeConfidence(mt.confidence);
      const mitigations = (mt.mitigations || []).map(m => `<li>${escHtml(m)}</li>`).join('');
      const platforms = (mt.platforms || []).join(', ');
      const killChain = (mt.kill_chain || []).join(' → ');
      return `<div class="modal-mitre-card">`
        + `<div class="modal-mitre-header">`
        + `<a href="${escHtml(mt.url)}" target="_blank" rel="noopener" class="mitre-link">${escHtml(mt.technique)} — ${escHtml(mt.name)}</a>`
        + `<span class="conf-badge conf-${conf}">${conf}</span>`
        + `</div>`
        + `${mt.detection ? `<div class="modal-mitre-section"><strong>Detection:</strong> ${escHtml(mt.detection)}</div>` : ''}`
        + `${mitigations ? `<div class="modal-mitre-section"><strong>Mitigations:</strong><ul>${mitigations}</ul></div>` : ''}`
        + `${platforms ? `<div class="modal-mitre-meta"><span>Platforms:</span> ${escHtml(platforms)}</div>` : ''}`
        + `${killChain ? `<div class="modal-mitre-meta"><span>Kill Chain:</span> ${escHtml(killChain)}</div>` : ''}`
        + `</div>`;
    }).join('');
  }

  const rows = [
    ['Severity', `<span class="sev-badge sev-${finding.severity || 'None'}">${finding.severity || 'None'}</span> · CVSS ${finding.cvss_score != null ? Number(finding.cvss_score).toFixed(1) : '-'} · ${escHtml(finding.cvss_vector || '-')}`],
    ['OWASP Category', escHtml(finding.owasp_category || '-')],
    ['MITRE ATT&CK', mitreHtml],
    ['Kill Chain', escHtml((finding.mitre_kill_chain || []).join(' → ') || '-')],
    ['URL / Path', escHtml(finding.affected_url || finding.url || finding.path || '-')],
    ['Parameter', escHtml(finding.parameter || finding.param || '-')],
    ['Detail', escHtml(finding.detail || finding.issue || finding.title || '-')],
    ['Payload', finding.payload ? `<pre>${escHtml(finding.payload)}</pre>` : '-'],
    ['Evidence', escHtml(finding.evidence || '-')],
    ['Recommendation', escHtml(finding.remediation || finding.recommendation || '-')],
  ];

  const content = document.getElementById('modalContent');
  if (content) {
    content.innerHTML = rows.map(([label, value]) => `<div class="modal-field"><div class="mf-label">${label}</div><div class="mf-value">${value}</div></div>`).join('');

    if (finding.screenshot) {
      const filename = String(finding.screenshot).split('/').pop().split('\\').pop();
      content.insertAdjacentHTML('beforeend', `<div class="modal-evidence"><div class="mf-label">Screenshot</div><img src="/api/evidence/${encodeURIComponent(filename)}" alt="Evidence screenshot" /></div>`);
    }
  }

  const aiContent = document.getElementById('modalAiContent');
  if (aiContent) aiContent.innerHTML = '';
}

function renderCvssGauge(score, vector) {
  const host = document.getElementById('cvssGauge');
  if (!host) return;
  host.innerHTML = '';

  if (!HAS_D3) {
    host.innerHTML = `<div class="mapping-empty">CVSS ${score.toFixed(1)} · ${escHtml(vector || '-')}</div>`;
    return;
  }

  const rect = host.getBoundingClientRect();
  const width = Math.max(260, Math.floor(rect.width));
  const height = Math.max(150, Math.floor(rect.height));

  const svg = d3.select(host).append('svg').attr('width', width).attr('height', height);
  const cx = width / 2;
  const cy = height * 0.76;
  const radius = Math.min(width * 0.42, height * 0.68);

  const bands = [
    { from: 0, to: 3.9, color: '#00ff9d' },
    { from: 4, to: 6.9, color: '#f5a623' },
    { from: 7, to: 8.9, color: '#ff6b35' },
    { from: 9, to: 10, color: '#ff1f4b' },
  ];

  const angle = d3.scaleLinear().domain([0, 10]).range([-Math.PI * 0.85, Math.PI * 0.85]);
  const arc = d3.arc().innerRadius(radius - 18).outerRadius(radius).startAngle(d => angle(d.from)).endAngle(d => angle(d.to));

  const g = svg.append('g').attr('transform', `translate(${cx},${cy})`);
  g.selectAll('path.band').data(bands).enter().append('path').attr('d', arc).attr('fill', d => d.color).attr('opacity', 0.8);

  const needleGroup = g.append('g');
  const targetAngle = angle(Math.max(0, Math.min(10, score || 0))) * (180 / Math.PI);

  needleGroup.append('line')
    .attr('x1', 0)
    .attr('y1', 0)
    .attr('x2', radius - 22)
    .attr('y2', 0)
    .attr('stroke', '#dff5ff')
    .attr('stroke-width', 3)
    .attr('stroke-linecap', 'round');

  needleGroup.append('circle').attr('r', 6).attr('fill', '#dff5ff');

  if (REDUCED_MOTION) {
    needleGroup.attr('transform', `rotate(${targetAngle})`);
  } else {
    needleGroup.attr('transform', 'rotate(-153)')
      .transition()
      .delay(200)
      .duration(680)
      .ease(d3.easeCubicOut)
      .attr('transform', `rotate(${targetAngle})`);
  }

  svg.append('text')
    .attr('x', cx)
    .attr('y', height * 0.38)
    .attr('text-anchor', 'middle')
    .style('font-family', 'var(--font-display)')
    .style('font-size', '24px')
    .style('fill', '#c8ddf5')
    .text(Number(score || 0).toFixed(1));

  svg.append('text')
    .attr('x', cx)
    .attr('y', height * 0.52)
    .attr('text-anchor', 'middle')
    .style('font-size', '10px')
    .style('fill', '#8ba3c0')
    .text('CVSS v3.1');

  svg.append('text')
    .attr('x', cx)
    .attr('y', height * 0.95)
    .attr('text-anchor', 'middle')
    .style('font-size', '10px')
    .style('fill', '#8ba3c0')
    .text(vector ? vector.slice(0, 110) : 'No CVSS vector');
}

function _runtimeSnapshot(scanData) {
  const runtime = (scanData && typeof scanData.runtime_config === 'object') ? scanData.runtime_config : {};
  const execution = (scanData && typeof scanData.execution_metadata === 'object') ? scanData.execution_metadata : {};

  const mode = runtime.mode || scanData?.mode || 'n/a';
  const threads = _toFiniteNumber(runtime.threads ?? scanData?.threads, 0);
  const timeoutSeconds = _toFiniteNumber(runtime.timeout_seconds ?? scanData?.timeout, 0);
  const requestDelaySeconds = _toFiniteNumber(runtime.request_delay_seconds ?? scanData?.request_delay, 0);
  const useBrowser = runtime.use_browser != null ? Boolean(runtime.use_browser) : Boolean(scanData?.use_browser);
  const crawlMode = runtime.crawl_mode || scanData?.crawl_mode || 'auto';
  const resolvedCrawlMode = execution.resolved_crawl_mode || crawlMode;
  const httpWorkers = _toFiniteNumber(execution.http_module_workers ?? threads, 0);
  const httpModuleCount = _toFiniteNumber(execution.http_module_count, 0);
  const browserModuleCount = _toFiniteNumber(execution.browser_module_count, useBrowser ? 2 : 0);
  const browserExecution = execution.browser_module_execution || (useBrowser ? 'sequential' : 'disabled');
  const browserTimeoutSeconds = _toFiniteNumber(execution.browser_module_timeout_seconds, 0);

  return {
    mode,
    threads,
    timeoutSeconds,
    requestDelaySeconds,
    useBrowser,
    crawlMode,
    resolvedCrawlMode,
    httpWorkers,
    httpModuleCount,
    browserModuleCount,
    browserExecution,
    browserTimeoutSeconds,
  };
}

function _runtimeMetric(label, value, hint) {
  return `<div class="runtime-pill">`
    + `<span class="runtime-label">${escHtml(label)}</span>`
    + `<span class="runtime-value">${escHtml(value)}</span>`
    + `${hint ? `<span class="runtime-hint">${escHtml(hint)}</span>` : ''}`
    + `</div>`;
}

function _renderRuntimeBehavior(scanData) {
  const wrappers = [
    { cardId: 'runtimeBehaviorCard', gridId: 'runtimeBehavior' },
    { cardId: 'executionSettings', gridId: 'executionSettingsGrid' },
  ];

  if (!scanData) {
    wrappers.forEach(({ cardId, gridId }) => {
      const card = document.getElementById(cardId);
      const grid = document.getElementById(gridId);
      if (card) card.style.display = 'none';
      if (grid) grid.innerHTML = '';
    });
    return;
  }

  const rt = _runtimeSnapshot(scanData);
  const crawlValue = rt.crawlMode === rt.resolvedCrawlMode
    ? rt.resolvedCrawlMode
    : `${rt.crawlMode} → ${rt.resolvedCrawlMode}`;
  const browserValue = rt.browserExecution === 'disabled'
    ? 'Disabled'
    : `${rt.browserExecution} (${rt.browserModuleCount} modules)`;

  const html = [
    _runtimeMetric('Mode', String(rt.mode).toUpperCase(), rt.useBrowser ? 'Browser engine enabled' : 'HTTP modules only'),
    _runtimeMetric('Threads', rt.threads > 0 ? String(rt.threads) : 'n/a', rt.httpWorkers > 0 ? `HTTP workers: ${rt.httpWorkers}` : ''),
    _runtimeMetric('Timeout', rt.timeoutSeconds > 0 ? `${rt.timeoutSeconds.toFixed(1)}s` : 'n/a', 'Per-request timeout'),
    _runtimeMetric('Request Delay', `${rt.requestDelaySeconds.toFixed(2)}s`, rt.requestDelaySeconds > 0 ? 'Throttle enabled' : 'No delay'),
    _runtimeMetric('Crawl Mode', crawlValue, 'Resolved at runtime'),
    _runtimeMetric('Browser Modules', browserValue, rt.browserTimeoutSeconds > 0 ? `Timeout budget: ${rt.browserTimeoutSeconds}s` : 'No browser timeout budget'),
    _runtimeMetric('HTTP Modules', rt.httpModuleCount > 0 ? String(rt.httpModuleCount) : 'Pending', 'Parallelized via thread pool'),
  ].join('');

  wrappers.forEach(({ cardId, gridId }) => {
    const card = document.getElementById(cardId);
    const grid = document.getElementById(gridId);
    if (!card || !grid) return;
    card.style.display = '';
    grid.innerHTML = html;
  });
}

function _setMappingFeedback(id, kind, message, retryFnName) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!message) {
    el.style.display = 'none';
    el.className = 'mapping-feedback';
    el.innerHTML = '';
    return;
  }
  el.style.display = '';
  el.className = `mapping-feedback ${kind || 'info'}`;
  const retry = retryFnName ? `<button type="button" class="btn-sm" onclick="${retryFnName}()">Retry</button>` : '';
  el.innerHTML = `<span>${escHtml(message)}</span>${retry}`;
}

function _renderMappingLoading(containerId, message) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="mapping-loading"><span class="spinner"></span><span>${escHtml(message)}</span></div>`;
}

function _renderMappingEmpty(containerId, message) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="mapping-empty">${escHtml(message)}</div>`;
}

function _extractOwaspCode(cat) {
  const m = String(cat || '').match(/A\d{2}/);
  return m ? m[0] : '';
}

function _sortOwaspEntries(entries) {
  const order = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];
  return entries.sort((a, b) => {
    const ac = _extractOwaspCode(a[0]);
    const bc = _extractOwaspCode(b[0]);
    const ai = order.indexOf(ac);
    const bi = order.indexOf(bc);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a[0].localeCompare(b[0]);
  });
}

function _simpleHash(text) {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
  }
  return hash >>> 0;
}

function _scanMitreCacheKey(scanData) {
  if (!scanData) return null;
  const sid = scanData.scan_id || activeScanId;
  if (!sid) return null;
  const findings = scanData.findings || [];
  const signature = findings.map(f => [
    f.id || '',
    f.type || f.module || '',
    f.severity || '',
    f.parameter || f.param || '',
    f.detail || '',
  ].join('|')).join('||');
  return `${sid}:${findings.length}:${_simpleHash(signature)}`;
}

function _normalizeConfidence(value) {
  const v = String(value || '').toLowerCase();
  if (v === 'high' || v === 'medium' || v === 'low') return v;
  return 'medium';
}

function _toFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

async function renderMitreBreakdown(findings, scanData) {
  const scanId = scanData?.scan_id || activeScanId;
  if (!scanId) return;

  const reqToken = ++mitreBreakdownReqToken;
  _setMappingFeedback('mitreFeedback', null, '');

  const stripEl = document.getElementById('mitreMatrixCoverage');
  const attackEl = document.getElementById('attackPaths');
  const controls = document.getElementById('mitreControls');
  const narrativeCard = document.getElementById('threatNarrativeCard');

  if (controls) controls.style.display = 'none';
  _renderMappingLoading('mitreBreakdown', 'Loading MITRE ATT&CK mapping...');
  if (stripEl) stripEl.innerHTML = '<div class="mapping-loading"><span class="spinner"></span><span>Loading matrix telemetry...</span></div>';
  if (attackEl) attackEl.innerHTML = '<div class="mapping-loading"><span class="spinner"></span><span>Loading kill-chain timeline...</span></div>';
  if (narrativeCard) narrativeCard.style.display = 'none';

  try {
    const cacheKey = _scanMitreCacheKey(scanData || { scan_id: scanId, findings: findings || [] });
    let mitreData = cacheKey ? mappingCache.mitreByScan[cacheKey] : null;

    if (!mitreData) {
      const res = await fetch(API + '/api/scan/' + scanId + '/mitre');
      if (!res.ok) throw new Error('Failed to load MITRE mapping');
      mitreData = await res.json();
      if (cacheKey) mappingCache.mitreByScan[cacheKey] = mitreData;
    }

    if (reqToken !== mitreBreakdownReqToken) return;

    const narrative = mitreData.threat_narrative;
    if (narrative && narrative.finding_count > 0) {
      if (narrativeCard) narrativeCard.style.display = '';
      const badge = document.getElementById('riskBadge');
      if (badge) {
        badge.className = 'risk-badge risk-' + narrative.risk_color;
        badge.textContent = `${narrative.risk_level} RISK`;
      }
      const narrativeEl = document.getElementById('threatNarrative');
      if (narrativeEl) narrativeEl.innerHTML = narrative.narrative;

      const metaEl = document.getElementById('threatMeta');
      if (metaEl) {
        metaEl.innerHTML = `<span class="threat-chip"><strong>${narrative.finding_count}</strong> findings</span>`
          + `<span class="threat-chip"><strong>${narrative.techniques_matched}</strong> techniques</span>`
          + `<span class="threat-chip"><strong>${narrative.tactics_covered}/14</strong> tactics</span>`
          + `<span class="threat-chip"><strong>${narrative.affected_endpoint_count}</strong> endpoints</span>`
          + (narrative.vuln_types || []).map(v => `<span class="threat-chip type-chip">${escHtml(v)}</span>`).join('');
      }
    }

    const coverage = mitreData.matrix_coverage || {};
    const tactics = Array.isArray(coverage.tactics) ? coverage.tactics : [];
    mitreBreakdownState.coverageTactics = tactics;
    renderMitreCoverageSummary(stripEl, coverage, tactics);
    syncMitreScenes(tactics);

    mitreBreakdownState.breakdown = Array.isArray(mitreData.mitre_breakdown) ? mitreData.mitre_breakdown : [];
    mitreBreakdownState.scanCacheKey = cacheKey || '';

    _updateMitreFilterControls();
    _highlightMatrixFilter(mitreBreakdownState.selectedTactic);
    _applyMitreBreakdownFilters();

    const paths = Array.isArray(mitreData.attack_paths) ? mitreData.attack_paths : [];
    renderKillChainTimeline(paths);
    sceneControllers.attackGraph?.setData(findings || [], paths);
  } catch (err) {
    if (reqToken !== mitreBreakdownReqToken) return;
    console.error('MITRE breakdown failed:', err);
    _setMappingFeedback('mitreFeedback', 'error', `Failed to load MITRE mapping: ${err.message}`, 'retryMitreBreakdown');
    _renderMappingEmpty('mitreBreakdown', 'Unable to display MITRE breakdown right now.');
    _renderMappingEmpty('mitreMatrixCoverage', 'MITRE matrix telemetry unavailable.');
    _renderMappingEmpty('attackPaths', 'Kill-chain timeline unavailable.');
  }
}

function renderMitreCoverageSummary(stripEl, coverage, tactics) {
  if (!stripEl) return;
  if (!Array.isArray(tactics) || !tactics.length) {
    stripEl.innerHTML = '<div class="mapping-empty">No tactic coverage data available.</div>';
    return;
  }

  const summary = `<div class="matrix-summary">`
    + `<span class="matrix-stat">${coverage.tactics_with_hits || 0}/${coverage.total_tactics || 14} tactics</span>`
    + `<span class="matrix-stat">${coverage.total_technique_hits || 0}/${coverage.total_techniques_in_db || 0} techniques</span>`
    + `<span class="matrix-stat">${coverage.overall_coverage_pct || 0}% coverage</span>`
    + `</div>`;

  const matrix = `<div class="matrix-heatmap">${tactics.map(t => {
    const heat = t.coverage_pct > 50 ? 'heat-high' : t.coverage_pct > 0 ? 'heat-med' : 'heat-none';
    const active = mitreBreakdownState.selectedTactic && mitreBreakdownState.selectedTactic === t.tactic ? ' active' : '';
    return `<button type="button" class="matrix-cell ${heat}${active}" data-tactic="${escHtml(t.tactic)}" title="${escHtml(t.tactic)} (${t.tactic_id})">`
      + `<div class="mc-name">${escHtml(t.tactic)}</div>`
      + `<div class="mc-id">${escHtml(t.tactic_id || '')}</div>`
      + `<div class="mc-stat">${t.detected_techniques}/${t.total_techniques}</div>`
      + `</button>`;
  }).join('')}</div>`;

  stripEl.innerHTML = summary + matrix;
  stripEl.querySelectorAll('.matrix-cell').forEach(cell => {
    cell.addEventListener('click', () => {
      const tactic = cell.dataset.tactic || '';
      const next = mitreBreakdownState.selectedTactic === tactic ? '' : tactic;
      mitreBreakdownState.selectedTactic = next;
      const sel = document.getElementById('mitreFilterTactic');
      if (sel) sel.value = next;
      _highlightMatrixFilter(next);
      _applyMitreBreakdownFilters();
    });
  });
}

function _updateMitreFilterControls() {
  const tacticSel = document.getElementById('mitreFilterTactic');
  const confidenceSel = document.getElementById('mitreFilterConfidence');
  const searchInput = document.getElementById('mitreFilterSearch');
  const controls = document.getElementById('mitreControls');
  if (!tacticSel || !confidenceSel || !searchInput || !controls) return;

  const breakdown = mitreBreakdownState.breakdown || [];
  controls.style.display = breakdown.length ? '' : 'none';

  const current = mitreBreakdownState.selectedTactic || '';
  const set = new Set();
  (mitreBreakdownState.coverageTactics || []).forEach(t => t?.tactic && set.add(t.tactic));
  breakdown.forEach(g => g?.tactic && set.add(g.tactic));

  tacticSel.innerHTML = '<option value="">All Tactics</option>';
  Array.from(set).forEach(tactic => {
    const opt = document.createElement('option');
    opt.value = tactic;
    opt.textContent = tactic;
    tacticSel.appendChild(opt);
  });

  mitreBreakdownState.selectedTactic = set.has(current) ? current : '';
  tacticSel.value = mitreBreakdownState.selectedTactic;
  confidenceSel.value = mitreBreakdownState.selectedConfidence;
  searchInput.value = mitreBreakdownState.search || '';
}

function _highlightMatrixFilter(selectedTactic) {
  document.querySelectorAll('#mitreMatrixCoverage .matrix-cell').forEach(cell => {
    cell.classList.toggle('active', !!selectedTactic && cell.dataset.tactic === selectedTactic);
  });
  sceneControllers.mitreMini?.setSelectedTactic(selectedTactic || '');
  sceneControllers.mitreFull?.setSelectedTactic(selectedTactic || '');
  syncTechniqueCloud(selectedTactic || '');
}

function _applyMitreBreakdownFilters() {
  const container = document.getElementById('mitreBreakdown');
  if (!container) return;

  const breakdown = mitreBreakdownState.breakdown || [];
  if (!breakdown.length) {
    _setMappingFeedback('mitreFeedback', null, '');
    container.innerHTML = '<div class="mapping-empty">No MITRE ATT&CK mappings found for this mission.</div>';
    return;
  }

  const search = mitreBreakdownState.search || '';
  const tacticFilter = mitreBreakdownState.selectedTactic || '';
  const confidenceFilter = mitreBreakdownState.selectedConfidence || '';

  let filteredGroups = breakdown;
  if (tacticFilter) filteredGroups = filteredGroups.filter(g => g.tactic === tacticFilter);

  const rowsByGroup = [];
  let visibleCount = 0;

  filteredGroups.forEach(group => {
    const techniques = (group.techniques || []).filter(tech => {
      const conf = _normalizeConfidence(tech.confidence);
      if (confidenceFilter && conf !== confidenceFilter) return false;
      if (search) {
        const haystack = `${tech.technique_id || ''} ${tech.name || ''}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });

    if (techniques.length) {
      rowsByGroup.push({ group, techniques });
      visibleCount += techniques.length;
    }
  });

  if (!rowsByGroup.length) {
    _setMappingFeedback('mitreFeedback', 'info', 'No techniques match current filters. Clear filters to view all mappings.');
    container.innerHTML = '<div class="mapping-empty">No techniques match selected filters.</div>';
    return;
  }

  const totalTechniques = breakdown.reduce((sum, g) => sum + (g.techniques || []).length, 0);
  if (visibleCount < totalTechniques) {
    _setMappingFeedback('mitreFeedback', 'info', `Showing ${visibleCount} of ${totalTechniques} mapped techniques.`);
  } else {
    _setMappingFeedback('mitreFeedback', null, '');
  }

  let html = '';
  rowsByGroup.forEach(({ group, techniques }) => {
    const maxCount = Math.max(...techniques.map(t => Number(t.finding_count || 0)), 1);
    html += `<div class="mitre-tactic-section">`
      + `<div class="mitre-tactic-bar-header">`
      + `<span class="tactic-name">${escHtml(group.tactic)}</span>`
      + `<span class="tactic-meta">${escHtml(group.tactic_id || '')} · ${techniques.length} visible / ${(group.techniques || []).length} total</span>`
      + `</div>`;

    techniques.forEach(tech => {
      const pct = (Number(tech.finding_count || 0) / maxCount) * 100;
      const conf = _normalizeConfidence(tech.confidence);
      html += `<div class="mitre-row">`
        + `<span class="label"><a href="${escHtml(tech.url)}" target="_blank" rel="noopener">${escHtml(tech.technique_id)} — ${escHtml(tech.name)}</a></span>`
        + `<span class="conf-dot conf-${conf}" title="${conf} confidence"></span>`
        + `<div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--high)"></div></div>`
        + `<div class="mitre-row-actions"><span class="count">${tech.finding_count || 0}</span>`
        + `<button class="btn-ai-mitre" onclick="event.stopPropagation();openMitreAiPanel('${escHtml(tech.technique_id)}','${escHtml(tech.name)}','${escHtml(group.tactic)}')">🧠 Ask AI</button></div>`
        + `</div>`;

      const evidence = Array.isArray(tech.finding_evidence) ? tech.finding_evidence : [];
      if (evidence.length) {
        html += '<div class="technique-evidence">';
        evidence.forEach(ev => {
          const sev = String(ev.severity || 'none').toLowerCase();
          html += `<div class="evidence-item">`
            + `<span class="sev-dot-sm sev-${escHtml(sev)}"></span>`
            + `<span class="ev-url" title="${escHtml(ev.url || '-')}">${escHtml(ev.url || '-')}</span>`
            + `<span class="ev-detail" title="${escHtml(ev.detail || '-')}">${escHtml(ev.detail || '-')}</span>`
            + `</div>`;
        });
        html += '</div>';
      }
    });

    html += '</div>';
  });

  container.innerHTML = html;
}

function renderKillChainTimeline(paths) {
  const container = document.getElementById('attackPaths');
  if (!container) return;

  if (!Array.isArray(paths) || !paths.length) {
    container.innerHTML = '<div class="mapping-empty">No attack path data available.</div>';
    return;
  }

  container.innerHTML = paths.map((phase, idx) => {
    const count = Number(phase.finding_count || (phase.findings || []).length || 0);
    return `<button type="button" class="killchain-node${idx === 0 ? ' active' : ''}" data-phase="${escHtml(phase.phase)}">`
      + `<div class="phase">${escHtml(phase.phase || 'Unknown')}</div>`
      + `<div class="meta">${count} finding${count !== 1 ? 's' : ''}</div>`
      + `</button>`;
  }).join('');

  container.querySelectorAll('.killchain-node').forEach(node => {
    node.addEventListener('mouseenter', () => {
      const phase = node.dataset.phase || '';
      sceneControllers.attackGraph?.highlightPhase(phase);
    });
    node.addEventListener('mouseleave', () => {
      sceneControllers.attackGraph?.highlightPhase('');
    });
    node.addEventListener('click', () => {
      const phase = node.dataset.phase || '';
      container.querySelectorAll('.killchain-node').forEach(n => n.classList.toggle('active', n === node));
      sceneControllers.attackGraph?.highlightPhase(phase);
    });
  });
}

function syncMitreScenes(tactics) {
  sceneControllers.mitreMini?.setCoverage(tactics || []);
  sceneControllers.mitreFull?.setCoverage(tactics || []);
  syncTechniqueCloud(mitreBreakdownState.selectedTactic || '');
}

function syncMitreFullScene() {
  if (!mitreBreakdownState.coverageTactics?.length) return;
  sceneControllers.mitreFull?.setCoverage(mitreBreakdownState.coverageTactics);
  sceneControllers.mitreFull?.setSelectedTactic(mitreBreakdownState.selectedTactic || '');
  syncTechniqueCloud(mitreBreakdownState.selectedTactic || '');
}

function syncTechniqueCloud(selectedTactic) {
  const cloudIds = ['mitreTechniqueCloud', 'mitreTechniqueCloudRoom'];
  const groups = mitreBreakdownState.breakdown || [];

  let techniques = [];
  if (selectedTactic) {
    const group = groups.find(g => g.tactic === selectedTactic);
    techniques = (group?.techniques || []).slice(0, 18);
  } else {
    techniques = groups.flatMap(g => g.techniques || []).slice(0, 18);
  }

  cloudIds.forEach(id => {
    const cloud = document.getElementById(id);
    if (!cloud) return;
    if (!techniques.length) {
      cloud.innerHTML = '<span class="technique-pill">No techniques in scope.</span>';
      return;
    }
    cloud.innerHTML = techniques.map(t => {
      const hit = selectedTactic ? ' highlight' : '';
      return `<button type="button" class="technique-pill${hit}" onclick="openMitreAiPanel('${escHtml(t.technique_id || '')}','${escHtml(t.name || '')}','${escHtml(selectedTactic || t.tactic || '')}')">${escHtml(t.technique_id || '')}</button>`;
    }).join('');
  });
}

function retryMitreBreakdown() {
  if (!activeScanId) return;
  const key = _scanMitreCacheKey({ scan_id: activeScanId, findings: allFindings });
  if (key) delete mappingCache.mitreByScan[key];
  renderMitreBreakdown(allFindings, { scan_id: activeScanId, findings: allFindings });
}

function retryMitreReference() {
  mappingCache.mitreReference = null;
  loadMitreRef();
}

function retryOwaspReference() {
  mappingCache.owaspReference = null;
  loadOwaspRef();
}

async function loadHistory() {
  const container = document.getElementById('historyTimeline');
  if (!container) return;
  container.innerHTML = '<div class="mapping-loading"><span class="spinner"></span><span>Loading archives...</span></div>';

  try {
    const res = await fetch(API + '/api/scans');
    if (!res.ok) throw new Error('Failed to load history');
    const scans = await res.json();

    if (!Array.isArray(scans) || !scans.length) {
      container.innerHTML = '<div class="mapping-empty">No missions archived yet.</div>';
      return;
    }

    container.innerHTML = scans.map(scan => {
      const summary = scan.summary || {};
      const c = Number(summary.critical || 0);
      const h = Number(summary.high || 0);
      const m = Number(summary.medium || 0);
      const l = Number(summary.low || 0);
      const n = Number(summary.none || 0);
      const total = Math.max(1, c + h + m + l + n);

      const statusClass = scan.status === 'failed' ? ' failed' : '';

      return `<div class="history-item${statusClass}">`
        + `<div class="history-top">`
        + `<div>`
        + `<div class="history-target">${escHtml(scan.target)}</div>`
        + `<div class="history-meta">${escHtml(scan.scan_id.slice(0, 8))} · ${escHtml(scan.mode)} · ${escHtml(scan.started_at)} · ${escHtml(scan.status)}</div>`
        + `</div>`
        + `<div class="history-meta">${Number(scan.findings_count || 0)} findings</div>`
        + `</div>`
        + `<div class="history-severity-bar">`
        + `<div class="history-seg seg-critical" style="width:${(c / total) * 100}%"></div>`
        + `<div class="history-seg seg-high" style="width:${(h / total) * 100}%"></div>`
        + `<div class="history-seg seg-medium" style="width:${(m / total) * 100}%"></div>`
        + `<div class="history-seg seg-low" style="width:${(l / total) * 100}%"></div>`
        + `<div class="history-seg seg-none" style="width:${(n / total) * 100}%"></div>`
        + `</div>`
        + `<div class="history-actions">`
        + `<button class="btn-sm" onclick="viewScan('${scan.scan_id}')">View</button>`
        + `${scan.status === 'running' ? `<button class="btn-cancel" onclick="cancelScan('${scan.scan_id}')">Cancel</button>` : ''}`
        + `<button class="btn-sm" onclick="deleteScan('${scan.scan_id}')">Delete</button>`
        + `</div>`
        + `</div>`;
    }).join('');
  } catch (err) {
    console.error('Failed to load history:', err);
    container.innerHTML = '<div class="mapping-empty">Unable to load mission archives.</div>';
  }
}

async function viewScan(scanId) {
  try {
    const res = await fetch(API + '/api/scan/' + scanId);
    if (!res.ok) throw new Error('Failed to load scan');
    const data = await res.json();

    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="scan"]').classList.add('active');
    document.getElementById('panel-scan').classList.add('active');

    document.getElementById('progressCard').style.display = '';
    document.getElementById('progressStage').textContent = data.current_stage || 'Ready';
    document.getElementById('progressPct').textContent = `${data.progress || 0}%`;
    document.getElementById('progressFill').style.width = `${data.progress || 0}%`;
    document.getElementById('findingsCount').textContent = data.findings_count || 0;
    document.getElementById('elapsed').textContent = formatDuration(Number(data.elapsed || 0));
    renderStageTimeline(data.stages || []);
    _renderRuntimeBehavior(data);

    setFormDisabled(true);
    const startBtn = document.getElementById('btnStart');
    startBtn.disabled = true;
    startBtn.textContent = 'Viewing Archive';
    document.getElementById('btnCancel').style.display = 'none';

    if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
      const elapsedText = formatDuration(Number(data.elapsed || 0));
      const totalTimeEl = document.getElementById('totalTimeDisplay');
      const statusLabel = data.status === 'completed' ? 'Mission complete' : data.status === 'cancelled' ? 'Mission cancelled' : 'Mission failed';
      totalTimeEl.innerHTML = `<span class="total-time-icon">⏱</span> ${statusLabel} in <strong>${elapsedText}</strong>`;
      totalTimeEl.className = 'total-time-display status-' + data.status;
      totalTimeEl.style.display = '';
    }

    if (Array.isArray(data.findings) && data.findings.length) {
      activeScanId = scanId;
      showResults(data);
    } else if (data.status === 'running') {
      activeScanId = scanId;
      startPolling();
      startScanTimer();
      setHeaderModeChip('Running');
      setRailScanning(true);
    } else {
      document.getElementById('resultsPanel').style.display = 'none';
    }
  } catch (err) {
    alert('Failed to load scan: ' + err.message);
  }
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan from archives?')) return;
  try {
    const res = await fetch(API + '/api/scan/' + scanId, { method: 'DELETE' });
    if (!res.ok) throw new Error('Delete failed');
    if (activeScanId === scanId) {
      activeScanId = null;
      resetScanForm();
    }
    loadHistory();
  } catch (err) {
    alert('Failed to delete scan: ' + err.message);
  }
}

async function cancelScan(scanId) {
  if (!confirm('Cancel this running scan?')) return;
  try {
    await fetch(API + '/api/scan/' + scanId + '/cancel', { method: 'POST' });
    loadHistory();
  } catch (err) {
    alert('Failed to cancel scan: ' + err.message);
  }
}

async function cancelActiveScan() {
  if (!activeScanId) return;
  const btn = document.getElementById('btnCancel');
  btn.disabled = true;
  btn.textContent = 'Aborting…';
  try {
    await fetch(API + '/api/scan/' + activeScanId + '/cancel', { method: 'POST' });
  } catch (err) {
    console.error('Cancel failed:', err);
  }
  btn.disabled = false;
  btn.textContent = '⬢ Abort';
}

async function loadOwaspRef() {
  const reqToken = ++owaspRefReqToken;
  _renderMappingLoading('owaspReference', 'Loading OWASP codex...');
  _setMappingFeedback('owaspRefFeedback', null, '');

  try {
    if (!mappingCache.owaspReference) {
      const res = await fetch(API + '/api/owasp');
      if (!res.ok) throw new Error('Failed to load OWASP mapping');
      mappingCache.owaspReference = await res.json();
    }

    if (reqToken !== owaspRefReqToken) return;

    const map = mappingCache.owaspReference || {};
    const entries = _sortOwaspEntries(Object.entries(map));
    if (!entries.length) {
      _renderMappingEmpty('owaspReference', 'No OWASP mapping available.');
      return;
    }

    const glyph = (code) => {
      if (code.startsWith('A01')) return '⎈';
      if (code.startsWith('A02')) return '◈';
      if (code.startsWith('A03')) return '⛓';
      if (code.startsWith('A04')) return '⬢';
      if (code.startsWith('A05')) return '⚠';
      if (code.startsWith('A06')) return '⌬';
      if (code.startsWith('A07')) return '◉';
      if (code.startsWith('A08')) return '◆';
      if (code.startsWith('A09')) return '☍';
      return '◌';
    };

    document.getElementById('owaspReference').innerHTML = entries.map(([id, name]) => {
      return `<div class="owasp-ref-card">`
        + `<span class="owasp-id">${escHtml(id)} · ${glyph(id)}</span>`
        + `<span class="owasp-name">${escHtml(name)}</span>`
        + `</div>`;
    }).join('');
  } catch (err) {
    if (reqToken !== owaspRefReqToken) return;
    _renderMappingEmpty('owaspReference', 'Unable to load OWASP codex right now.');
    _setMappingFeedback('owaspRefFeedback', 'error', `Failed to load OWASP mapping: ${err.message}`, 'retryOwaspReference');
  }
}

async function loadMitreRef() {
  const reqToken = ++mitreRefReqToken;
  _setMappingFeedback('mitreRefFeedback', null, '');
  _renderMappingLoading('mitreReference', 'Loading MITRE technique reference...');

  const overview = document.getElementById('mitreTacticOverview');
  if (overview) overview.innerHTML = '<div class="mapping-loading"><span class="spinner"></span><span>Loading matrix room...</span></div>';

  try {
    if (!mappingCache.mitreReference) {
      const [tacRes, techRes] = await Promise.all([
        fetch(API + '/api/mitre/tactics'),
        fetch(API + '/api/mitre'),
      ]);
      if (!tacRes.ok || !techRes.ok) throw new Error('Failed to load MITRE reference');
      const [tactics, techniques] = await Promise.all([tacRes.json(), techRes.json()]);
      mappingCache.mitreReference = { tactics, techniques };
    }

    if (reqToken !== mitreRefReqToken) return;

    const tactics = mappingCache.mitreReference.tactics || [];
    const techniques = mappingCache.mitreReference.techniques || {};

    document.getElementById('mitreTechCount').textContent = String(Object.keys(techniques).length);

    if (overview) {
      if (!tactics.length) {
        overview.innerHTML = '<div class="mapping-empty">No tactics available.</div>';
      } else {
        overview.innerHTML = tactics.map(tac => {
          const techCount = Object.values(techniques).filter(t => t.tactic_id === tac.id || (t.tactics || []).some(tt => tt.id === tac.id)).length;
          return `<a href="${escHtml(tac.url)}" target="_blank" rel="noopener" class="tactic-overview-card">`
            + `<div class="toc-id">${escHtml(tac.id)}</div>`
            + `<div class="toc-name">${escHtml(tac.name)}</div>`
            + `<div class="toc-count">${techCount} techniques</div>`
            + `<div class="toc-desc">${escHtml(tac.description || '')}</div>`
            + `</a>`;
        }).join('');
      }
    }

    const byTactic = {};
    for (const [tid, info] of Object.entries(techniques)) {
      const allTactics = info.tactics || [{ id: info.tactic_id, name: info.tactic }];
      allTactics.forEach(tac => {
        if (!byTactic[tac.name]) byTactic[tac.name] = { id: tac.id, techs: [] };
        byTactic[tac.name].techs.push({ id: tid, ...info });
      });
    }

    const order = {};
    tactics.forEach(t => { order[t.name] = t.ordinal; });

    const names = Object.keys(byTactic).sort((a, b) => (order[a] || 99) - (order[b] || 99));
    if (!names.length) {
      _renderMappingEmpty('mitreReference', 'No MITRE techniques available.');
      return;
    }

    let html = '';
    names.forEach(name => {
      const group = byTactic[name];
      html += `<div class="mitre-tactic-group" data-tactic="${escHtml(name)}">`
        + `<h3 class="mitre-tactic-header">${escHtml(name)}<span class="mitre-tactic-id">${escHtml(group.id || '')}</span><span class="mitre-tactic-count">${group.techs.length}</span></h3>`
        + `<div class="mitre-technique-list">`;

      group.techs.sort((a, b) => a.id.localeCompare(b.id)).forEach(t => {
        const platforms = (t.platforms || []).join(', ');
        const dataSources = (t.data_sources || []).join(', ');
        const mitigations = (t.mitigations || []).map(m => `<li>${escHtml(m)}</li>`).join('');
        const killChain = (t.kill_chain || []).join(' → ');
        const subBadge = t.is_subtechnique ? '<span class="sub-technique-badge">SUB</span>' : '';
        const weightClass = t.severity_weight >= 8 ? 'weight-high' : t.severity_weight >= 5 ? 'weight-med' : 'weight-low';

        html += `<div class="mitre-ref-card-v2" data-technique-id="${escHtml(t.id)}" data-technique-name="${escHtml(t.name)}" data-tactic="${escHtml(name)}" data-platforms="${escHtml(platforms)}" tabindex="0" role="button" aria-expanded="false">`
          + `<div class="mrc-header">`
          + `<span class="mitre-tid">${escHtml(t.id)}</span>${subBadge}`
          + `<span class="mitre-tname">${escHtml(t.name)}</span>`
          + `<span class="weight-badge ${weightClass}">${Number(t.severity_weight || 0).toFixed(1)}</span>`
          + `<button class="btn-ai-mitre" onclick="event.stopPropagation();openMitreAiPanel('${escHtml(t.id)}','${escHtml(t.name)}','${escHtml(name)}')">🧠</button>`
          + `<a href="${escHtml(t.url)}" target="_blank" rel="noopener" class="mrc-link" onclick="event.stopPropagation()">↗</a>`
          + `</div>`
          + `<div class="mrc-desc">${escHtml(t.description || '')}</div>`
          + `<div class="mrc-details">`
          + `${t.detection ? `<div class="mrc-section"><div class="mrc-label">Detection</div><div class="mrc-text">${escHtml(t.detection)}</div></div>` : ''}`
          + `${mitigations ? `<div class="mrc-section"><div class="mrc-label">Mitigations</div><ul class="mrc-list">${mitigations}</ul></div>` : ''}`
          + `${platforms ? `<div class="mrc-section"><div class="mrc-label">Platforms</div><div class="mrc-tags">${(t.platforms || []).map(p => `<span class="mrc-tag">${escHtml(p)}</span>`).join('')}</div></div>` : ''}`
          + `${dataSources ? `<div class="mrc-section"><div class="mrc-label">Data Sources</div><div class="mrc-text">${escHtml(dataSources)}</div></div>` : ''}`
          + `${killChain ? `<div class="mrc-section"><div class="mrc-label">Kill Chain</div><div class="mrc-text">${escHtml(killChain)}</div></div>` : ''}`
          + `</div>`
          + `</div>`;
      });

      html += '</div></div>';
    });

    const container = document.getElementById('mitreReference');
    container.innerHTML = html;

    container.querySelectorAll('.mitre-ref-card-v2').forEach(card => {
      card.addEventListener('click', () => {
        const expanded = card.classList.toggle('expanded');
        card.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      });
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const expanded = card.classList.toggle('expanded');
          card.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        }
      });
    });

    const search = document.getElementById('mitreRefSearch');
    if (search) _filterMitreReference(search.value || '');
  } catch (err) {
    if (reqToken !== mitreRefReqToken) return;
    console.error('Failed to load MITRE reference:', err);
    _renderMappingEmpty('mitreReference', 'Unable to load MITRE reference right now.');
    _setMappingFeedback('mitreRefFeedback', 'error', `Failed to load MITRE reference: ${err.message}`, 'retryMitreReference');
  }
}

function _filterMitreReference(rawQuery) {
  const query = String(rawQuery || '').trim().toLowerCase();
  const cards = document.querySelectorAll('#mitreReference .mitre-ref-card-v2');
  const groups = document.querySelectorAll('#mitreReference .mitre-tactic-group');

  cards.forEach(card => {
    if (!query) {
      card.classList.remove('mitre-hidden');
      return;
    }
    const haystack = [
      card.dataset.techniqueId || '',
      card.dataset.techniqueName || '',
      card.dataset.tactic || '',
      card.dataset.platforms || '',
    ].join(' ').toLowerCase();
    card.classList.toggle('mitre-hidden', !haystack.includes(query));
  });

  groups.forEach(group => {
    const visible = group.querySelector('.mitre-ref-card-v2:not(.mitre-hidden)');
    group.classList.toggle('mitre-hidden-group', !visible);
  });
}

function _sanitizeAiErrorMessage(message, code, status) {
  const raw = String(message || '').trim();
  const lower = raw.toLowerCase();

  if (code === 'AI_CONFIG_MISSING') return 'AI service is not configured for this environment.';
  if (code === 'AI_UPSTREAM_UNAVAILABLE') return 'AI service is temporarily unavailable. Please retry in a moment.';
  if (code === 'AI_INTERNAL_ERROR') return 'AI request failed due to an internal service error. Please retry.';

  if (!raw) {
    if (status >= 500) return 'AI service is temporarily unavailable. Please retry in a moment.';
    return 'AI request could not be completed.';
  }

  if (lower.includes('gemini') || lower.includes('api key') || lower.includes('pentavault_gemini_api_keys') || lower.includes('gemini_api_key')) {
    return 'AI service is not configured for this environment.';
  }
  if (lower.includes('failed to fetch') || lower.includes('networkerror') || lower.includes('load failed')) {
    return 'Unable to reach the AI service endpoint. Check your connection and retry.';
  }
  if (lower.includes('timeout')) return 'AI service timed out. Please retry in a moment.';
  if (lower.includes('all api keys/models exhausted') || lower.includes('upstream')) {
    return 'AI service is temporarily unavailable. Please retry in a moment.';
  }
  return raw;
}

function _parseAiErrorPayload(payload, statusCode) {
  const detail = payload?.detail;
  let code = '';
  let retryable = statusCode >= 500;
  let message = '';

  if (detail && typeof detail === 'object') {
    if (typeof detail.code === 'string') code = detail.code;
    if (typeof detail.retryable === 'boolean') retryable = detail.retryable;
    if (typeof detail.message === 'string') {
      message = detail.message;
    } else if (Array.isArray(detail.errors) && detail.errors.length) {
      message = detail.errors.join('; ');
    }
  } else if (typeof detail === 'string') {
    message = detail;
  }

  return {
    code,
    retryable,
    message: _sanitizeAiErrorMessage(message, code, statusCode),
  };
}

async function _postAiJson(path, payload) {
  let res;
  try {
    res = await fetch(API + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    const e = new Error(_sanitizeAiErrorMessage(err?.message || 'Failed to fetch', '', 0));
    e.retryable = true;
    e.code = 'NETWORK_UNREACHABLE';
    throw e;
  }

  if (!res.ok) {
    const payloadErr = await res.json().catch(() => ({}));
    const parsed = _parseAiErrorPayload(payloadErr, res.status);
    const e = new Error(parsed.message || 'AI request failed');
    e.retryable = parsed.retryable;
    e.code = parsed.code;
    e.status = res.status;
    throw e;
  }

  return res.json();
}

async function aiAnalyze() {
  if (!activeScanId) {
    alert('No active scan to analyze.');
    return;
  }
  const btn = document.getElementById('btnAiAnalyze');
  const content = document.getElementById('aiAnalysisContent');
  btn.disabled = true;
  btn.textContent = '⏳ Analyzing...';
  content.innerHTML = '<div class="ai-loading"><span class="spinner"></span><span>AI is analyzing mission findings...</span></div>';

  try {
    const data = await _postAiJson('/api/ai/analyze', { scan_id: activeScanId });
    content.innerHTML = '<div class="ai-response">' + sanitizeAiHtml(data.analysis) + '</div>';
  } catch (err) {
    const hint = err?.retryable ? ' Please retry in a moment.' : '';
    content.innerHTML = '<div class="ai-error">AI analysis failed: ' + escHtml(String(err.message || 'AI request failed') + hint) + '</div>';
  }

  btn.disabled = false;
  btn.textContent = '✨ Generate Analysis';
}

async function aiExecutiveSummary() {
  if (!activeScanId) {
    alert('No active scan.');
    return;
  }

  const btn = document.getElementById('btnAiExec');
  const content = document.getElementById('aiExecContent');
  btn.disabled = true;
  btn.textContent = '⏳ Generating...';
  content.innerHTML = '<div class="ai-loading"><span class="spinner"></span><span>AI is preparing executive summary...</span></div>';

  try {
    const data = await _postAiJson('/api/ai/executive-summary', { scan_id: activeScanId });
    content.innerHTML = '<div class="ai-response">' + sanitizeAiHtml(data.summary) + '</div>';
  } catch (err) {
    const hint = err?.retryable ? ' Please retry in a moment.' : '';
    content.innerHTML = '<div class="ai-error">AI summary failed: ' + escHtml(String(err.message || 'AI request failed') + hint) + '</div>';
  }

  btn.disabled = false;
  btn.textContent = '✨ Generate Summary';
}

async function aiRemediateModal() {
  if (!activeScanId || currentModalFindingIdx == null || currentModalFindingIdx < 0) {
    alert('No finding selected.');
    return;
  }

  const btn = document.getElementById('btnAiRemediate');
  const content = document.getElementById('modalAiContent');
  btn.disabled = true;
  btn.textContent = '⏳ Generating...';
  content.innerHTML = '<div class="ai-loading"><span class="spinner"></span><span>AI is generating remediation guidance...</span></div>';

  try {
    const data = await _postAiJson('/api/ai/remediate', { scan_id: activeScanId, finding_index: currentModalFindingIdx });
    content.innerHTML = '<div class="ai-response">' + sanitizeAiHtml(data.remediation) + '</div>';
  } catch (err) {
    const hint = err?.retryable ? ' Please retry in a moment.' : '';
    content.innerHTML = '<div class="ai-error">AI remediation failed: ' + escHtml(String(err.message || 'AI request failed') + hint) + '</div>';
  }

  btn.disabled = false;
  btn.textContent = '🧠 AI Remediation Guide';
}

function openMitreAiPanel(techId, techName, tactic) {
  _mitreAiTechId = techId;
  _mitreAiTechName = techName;
  _mitreAiTactic = tactic;

  document.getElementById('mitreAiTitle').textContent = `${techId} — ${techName}`;
  document.getElementById('mitreAiSubtitle').textContent = `Tactic: ${tactic} · Contextual mission analysis`;
  document.getElementById('mitreAiContent').innerHTML = '';
  document.getElementById('mitreAiQuestion').value = '';
  document.getElementById('mitreAiOverlay').style.display = 'flex';

  _callMitreAiExplain(null, true);
}

function closeMitreAiPanel() {
  document.getElementById('mitreAiOverlay').style.display = 'none';
}

async function _callMitreAiExplain(question, isInitial) {
  if (!activeScanId) {
    alert('No active scan.');
    return;
  }

  const content = document.getElementById('mitreAiContent');
  const btn = document.getElementById('btnMitreAiAsk');

  if (isInitial) {
    content.innerHTML = `<div class="ai-loading"><span class="spinner"></span><span>AI analyzing ${escHtml(_mitreAiTechId)} in mission context...</span></div>`;
  } else {
    const history = document.createElement('div');
    history.className = 'mitre-ai-history';
    history.innerHTML = `<div class="mitre-ai-q">${escHtml(question)}</div><div class="mitre-ai-a"><div class="ai-loading"><span class="spinner"></span><span>AI is thinking...</span></div></div>`;
    content.appendChild(history);
    history.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  btn.disabled = true;

  try {
    const data = await _postAiJson('/api/ai/mitre-explain', {
      scan_id: activeScanId,
      technique_id: _mitreAiTechId,
      technique_name: _mitreAiTechName,
      tactic: _mitreAiTactic,
      question: question || '',
    });

    if (isInitial) {
      content.innerHTML = '<div class="ai-response">' + sanitizeAiHtml(data.explanation) + '</div>';
    } else {
      const target = content.querySelector('.mitre-ai-history:last-child .mitre-ai-a');
      if (target) target.innerHTML = '<div class="ai-response">' + sanitizeAiHtml(data.explanation) + '</div>';
    }
  } catch (err) {
    const hint = err?.retryable ? ' Please retry in a moment.' : '';
    const html = '<div class="ai-error">AI explain failed: ' + escHtml(String(err.message || 'AI request failed') + hint) + '</div>';
    if (isInitial) {
      content.innerHTML = html;
    } else {
      const target = content.querySelector('.mitre-ai-history:last-child .mitre-ai-a');
      if (target) target.innerHTML = html;
    }
  }

  btn.disabled = false;
}

function askMitreAiFollowup() {
  const input = document.getElementById('mitreAiQuestion');
  const question = input.value.trim();
  if (!question) return;
  input.value = '';
  _callMitreAiExplain(question, false);
}

function askMitreAiSuggestion(el) {
  const question = el.textContent.trim();
  document.getElementById('mitreAiQuestion').value = '';
  _callMitreAiExplain(question, false);
}

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
    f.title || f.type || f.module || '',
    f.affected_url || f.url || f.path || '',
    f.owasp_category || '',
    (f.mitre_attack || []).map(mt => mt.technique + ' ' + mt.name).join('; '),
    f.cvss_score != null ? f.cvss_score : '',
    f.cvss_vector || '',
    f.parameter || f.param || '',
    f.detail || f.issue || f.title || '',
    f.payload || '',
    f.evidence || '',
    f.remediation || f.recommendation || '',
  ]);

  const csv = [headers, ...rows]
    .map(row => row.map(cell => '"' + String(cell).replace(/"/g, '""') + '"').join(','))
    .join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  _downloadBlob(blob, 'scan_results.csv');
}

function downloadTXT() {
  if (!allFindings.length) return;
  const divider = '='.repeat(70);
  const lines = ['VULNERABILITY SCAN RESULTS', divider, `Total findings: ${allFindings.length}`, ''];

  allFindings.forEach((f, idx) => {
    lines.push('-'.repeat(70));
    lines.push(`Finding #${idx + 1}`);
    lines.push('-'.repeat(70));
    lines.push('Severity      : ' + (f.severity || 'N/A'));
    lines.push('Type          : ' + (f.title || f.type || f.module || 'N/A'));
    lines.push('URL           : ' + (f.affected_url || f.url || f.path || 'N/A'));
    lines.push('OWASP         : ' + (f.owasp_category || 'N/A'));
    lines.push('MITRE ATT&CK  : ' + ((f.mitre_attack || []).map(mt => `${mt.technique} — ${mt.name}`).join(', ') || 'N/A'));
    lines.push('CVSS Score    : ' + (f.cvss_score != null ? f.cvss_score : 'N/A'));
    lines.push('CVSS Vector   : ' + (f.cvss_vector || 'N/A'));
    lines.push('Parameter     : ' + (f.parameter || f.param || 'N/A'));
    lines.push('Detail        : ' + (f.detail || f.issue || f.title || 'N/A'));
    lines.push('Payload       : ' + (f.payload || 'N/A'));
    lines.push('Evidence      : ' + (f.evidence || 'N/A'));
    lines.push('Recommendation: ' + (f.remediation || f.recommendation || 'N/A'));
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

async function downloadPDF() {
  if (!activeScanId) {
    alert('No scan to export.');
    return;
  }
  try {
    const res = await fetch(API + '/api/scan/' + activeScanId + '/report/pdf');
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'PDF generation failed');
    }
    const blob = await res.blob();
    _downloadBlob(blob, 'PentaVault_Report.pdf');
  } catch (err) {
    alert('PDF download failed: ' + err.message);
  }
}

async function downloadDOCX() {
  if (!activeScanId) {
    alert('No scan to export.');
    return;
  }
  try {
    const res = await fetch(API + '/api/scan/' + activeScanId + '/report/docx');
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'DOCX generation failed');
    }
    const blob = await res.blob();
    _downloadBlob(blob, 'PentaVault_Report.docx');
  } catch (err) {
    alert('DOCX download failed: ' + err.message);
  }
}

function initVisualScenes() {
  sceneControllers.globe = initGlobeScene();
  sceneControllers.progress = initProgressScene();
  sceneControllers.attackGraph = initAttackGraphScene();
  sceneControllers.mitreMini = initMitreMatrixScene('mitreMatrixScene', 'mitreTechniqueCloud');
  sceneControllers.mitreFull = initMitreMatrixScene('mitreMatrixFullScene', 'mitreTechniqueCloudRoom');
}

function mountThreeRuntime(containerId, setupFn, fallbackText) {
  const host = document.getElementById(containerId);
  if (!host) return null;

  if (!HAS_THREE) {
    host.innerHTML = `<div class="mapping-empty">${escHtml(fallbackText || '3D visualization unavailable in this environment.')}</div>`;
    return null;
  }

  const width = Math.max(80, host.clientWidth || 320);
  const height = Math.max(80, host.clientHeight || 240);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(width, height, false);

  host.innerHTML = '';
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 200);
  camera.position.set(0, 0, 7);

  const controls = (!REDUCED_MOTION && THREE.OrbitControls)
    ? new THREE.OrbitControls(camera, renderer.domElement)
    : null;
  if (controls) {
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.35;
  }

  const runtime = {
    host,
    renderer,
    scene,
    camera,
    controls,
    clock: new THREE.Clock(),
    animate: () => {},
    resize: () => {
      const w = Math.max(80, host.clientWidth || width);
      const h = Math.max(80, host.clientHeight || height);
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    },
  };

  setupFn(runtime);
  sceneRuntimes.push(runtime);

  if (!renderLoopStarted) {
    startRenderLoop();
  }

  if (!resizeBound) {
    window.addEventListener('resize', () => {
      sceneRuntimes.forEach(rt => rt.resize());
    });
    resizeBound = true;
  }

  return runtime;
}

function startRenderLoop() {
  renderLoopStarted = true;
  const loop = () => {
    sceneRuntimes.forEach(rt => {
      if (!rt.host.isConnected) return;
      const delta = rt.clock.getDelta();
      rt.animate(delta);
      if (rt.controls) rt.controls.update();
      rt.renderer.render(rt.scene, rt.camera);
    });
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}

function latLngToVector3(lat, lng, radius = 1.6) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
}

function initGlobeScene() {
  if (REDUCED_MOTION) {
    const host = document.getElementById('launchGlobeScene');
    if (host) host.innerHTML = '<div class="mapping-empty">Reduced motion enabled · static globe mode active.</div>';
    return {
      setTarget: () => {},
    };
  }

  const runtime = mountThreeRuntime('launchGlobeScene', (rt) => {
    const ambient = new THREE.AmbientLight(0x8fb8d9, 0.46);
    const key = new THREE.PointLight(0x33ddff, 1.4, 30);
    key.position.set(4, 3, 5);
    rt.scene.add(ambient, key);

    const globeGroup = new THREE.Group();
    rt.scene.add(globeGroup);

    const globe = new THREE.Mesh(
      new THREE.SphereGeometry(1.6, 48, 48),
      new THREE.MeshStandardMaterial({
        color: 0x0f2232,
        metalness: 0.25,
        roughness: 0.72,
      })
    );
    globeGroup.add(globe);

    const wire = new THREE.Mesh(
      new THREE.SphereGeometry(1.603, 36, 36),
      new THREE.MeshBasicMaterial({
        color: 0x1d4e72,
        transparent: true,
        opacity: 0.22,
        wireframe: true,
      })
    );
    globeGroup.add(wire);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.76, 36, 36),
      new THREE.MeshBasicMaterial({
        color: 0x00d4ff,
        transparent: true,
        opacity: 0.11,
        blending: THREE.AdditiveBlending,
        side: THREE.BackSide,
      })
    );
    globeGroup.add(atmosphere);

    const marker = new THREE.Mesh(
      new THREE.SphereGeometry(0.06, 20, 20),
      new THREE.MeshBasicMaterial({ color: 0xff1f4b })
    );
    globeGroup.add(marker);

    const ring = new THREE.Mesh(
      new THREE.RingGeometry(0.09, 0.12, 24),
      new THREE.MeshBasicMaterial({ color: 0xff1f4b, side: THREE.DoubleSide, transparent: true, opacity: 0.72 })
    );
    globeGroup.add(ring);

    const arcs = new THREE.Group();
    globeGroup.add(arcs);

    let targetLat = 0;
    let targetLng = 0;
    let hover = false;

    const buildArcs = () => {
      arcs.clear();
      const origins = [
        { lat: 37, lng: -122 },
        { lat: 51, lng: 0 },
        { lat: 35, lng: 139 },
        { lat: -33, lng: 151 },
      ];

      origins.forEach((origin, idx) => {
        const start = latLngToVector3(origin.lat, origin.lng, 1.62);
        const end = latLngToVector3(targetLat, targetLng, 1.62);
        const mid = start.clone().add(end).multiplyScalar(0.5).normalize().multiplyScalar(2.25 + idx * 0.05);
        const curve = new THREE.CatmullRomCurve3([start, mid, end]);
        const points = curve.getPoints(42);
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const line = new THREE.Line(
          geometry,
          new THREE.LineBasicMaterial({ color: 0xff6b35, transparent: true, opacity: 0.75 })
        );
        arcs.add(line);
      });
    };

    const setTarget = (lat, lng) => {
      targetLat = lat;
      targetLng = lng;
      const vec = latLngToVector3(lat, lng, 1.6);
      marker.position.copy(vec);
      ring.position.copy(vec.clone().multiplyScalar(1.01));
      ring.lookAt(vec.clone().multiplyScalar(2));
      buildArcs();
      if (rt.controls) {
        rt.controls.target.copy(vec.clone().multiplyScalar(0.18));
      }
    };

    setTarget(12, 72);

    rt.host.addEventListener('mouseenter', () => {
      hover = true;
      if (rt.controls) rt.controls.autoRotate = false;
    });
    rt.host.addEventListener('mouseleave', () => {
      hover = false;
      if (rt.controls) rt.controls.autoRotate = true;
    });

    rt.host.addEventListener('click', () => {
      const focus = latLngToVector3(targetLat, targetLng, 2.8);
      rt.camera.position.lerp(focus, 0.35);
      rt.camera.lookAt(marker.position);
    });

    rt.animate = (delta) => {
      if (!hover) globeGroup.rotation.y += delta * 0.16;
      const pulse = 1 + Math.sin(performance.now() * 0.004) * 0.2;
      marker.scale.setScalar(pulse);
      ring.scale.setScalar(1 + Math.sin(performance.now() * 0.0035) * 0.28);
      ring.material.opacity = 0.44 + Math.sin(performance.now() * 0.004) * 0.2;
    };

    rt.api = {
      setTarget,
    };
  }, 'Threat globe unavailable.');

  if (!runtime || !runtime.api) {
    return { setTarget: () => {} };
  }

  return runtime.api;
}

function initProgressScene() {
  if (REDUCED_MOTION) {
    const host = document.getElementById('progress3dScene');
    if (host) host.innerHTML = '<div class="mapping-empty">Reduced motion enabled · static scan engine.</div>';
    return {
      setProgress: () => {},
      pulseStage: () => {},
    };
  }

  const runtime = mountThreeRuntime('progress3dScene', (rt) => {
    const ambient = new THREE.AmbientLight(0x8cc8f5, 0.42);
    const key = new THREE.PointLight(0x00d4ff, 1.2, 30);
    key.position.set(3, 4, 6);
    rt.scene.add(ambient, key);

    const count = 1200;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const u = Math.random() * Math.PI * 2;
      const v = Math.random() * Math.PI * 2;
      const R = 1.8;
      const r = 0.58;
      const x = (R + r * Math.cos(v)) * Math.cos(u);
      const y = (R + r * Math.cos(v)) * Math.sin(u);
      const z = r * Math.sin(v);
      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;
    }

    const pGeom = new THREE.BufferGeometry();
    pGeom.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const pMat = new THREE.PointsMaterial({
      color: 0x00d4ff,
      size: 0.035,
      transparent: true,
      opacity: 0.72,
      depthWrite: false,
    });

    const points = new THREE.Points(pGeom, pMat);
    rt.scene.add(points);

    const ringBg = new THREE.Mesh(
      new THREE.TorusGeometry(2.45, 0.08, 12, 100),
      new THREE.MeshBasicMaterial({ color: 0x1c2d3f, transparent: true, opacity: 0.72 })
    );
    ringBg.rotation.x = Math.PI / 2;
    rt.scene.add(ringBg);

    let progressArc = new THREE.Mesh(
      new THREE.TorusGeometry(2.45, 0.11, 12, 100, 0.01),
      new THREE.MeshBasicMaterial({ color: 0x00ff9d, transparent: true, opacity: 0.95 })
    );
    progressArc.rotation.x = Math.PI / 2;
    rt.scene.add(progressArc);

    let progress = 0;
    let pulse = 0;

    const setProgress = (pct) => {
      progress = Math.max(0, Math.min(100, Number(pct || 0)));
      rt.scene.remove(progressArc);
      progressArc.geometry.dispose();
      progressArc = new THREE.Mesh(
        new THREE.TorusGeometry(2.45, 0.11, 12, 120, Math.max(0.01, (Math.PI * 2) * (progress / 100))),
        new THREE.MeshBasicMaterial({ color: progress >= 95 ? 0x00ff9d : 0x00d4ff, transparent: true, opacity: 0.95 })
      );
      progressArc.rotation.x = Math.PI / 2;
      rt.scene.add(progressArc);
    };

    const pulseStage = () => {
      pulse = 1.0;
    };

    rt.animate = (delta) => {
      points.rotation.z += delta * 0.22;
      points.rotation.y += delta * 0.16;
      if (pulse > 0) {
        pulse -= delta * 1.4;
      }
      const k = 1 + Math.max(0, pulse) * 0.18;
      ringBg.scale.setScalar(k);
      ringBg.material.opacity = 0.55 + Math.max(0, pulse) * 0.25;
      progressArc.rotation.z += delta * 0.14;
    };

    rt.api = {
      setProgress,
      pulseStage,
    };
  }, 'Scan engine visualization unavailable.');

  if (!runtime || !runtime.api) {
    return {
      setProgress: () => {},
      pulseStage: () => {},
    };
  }

  return runtime.api;
}

function initAttackGraphScene() {
  if (REDUCED_MOTION) {
    const host = document.getElementById('attackGraphScene');
    if (host) host.innerHTML = '<div class="mapping-empty">Reduced motion enabled · static attack graph mode.</div>';
    return {
      setData: () => {},
      highlightPhase: () => {},
    };
  }

  const runtime = mountThreeRuntime('attackGraphScene', (rt) => {
    const ambient = new THREE.AmbientLight(0x9ec2e8, 0.5);
    const key = new THREE.PointLight(0x00d4ff, 1.1, 35);
    key.position.set(4, 4, 6);
    rt.scene.add(ambient, key);

    rt.camera.position.set(0, 0.8, 8.4);
    if (rt.controls) {
      rt.controls.autoRotate = true;
      rt.controls.autoRotateSpeed = 0.2;
      rt.controls.minDistance = 4;
      rt.controls.maxDistance = 14;
    }

    const root = new THREE.Group();
    const nodesGroup = new THREE.Group();
    const edgesGroup = new THREE.Group();
    root.add(edgesGroup);
    root.add(nodesGroup);
    rt.scene.add(root);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(2, 2);
    const severityColor = {
      Critical: 0xff1f4b,
      High: 0xff6b35,
      Medium: 0xf5a623,
      Low: 0x00ff9d,
      None: 0x4fa5ff,
      Info: 0x4fa5ff,
    };

    let nodeMeshes = [];
    let phaseLookup = new Map();
    let hovered = null;
    let focusedPhase = '';

    function clearGraph() {
      nodeMeshes.forEach(mesh => {
        mesh.geometry.dispose();
        mesh.material.dispose();
      });
      edgesGroup.children.forEach(line => {
        line.geometry.dispose();
        line.material.dispose();
      });
      nodesGroup.clear();
      edgesGroup.clear();
      nodeMeshes = [];
      phaseLookup = new Map();
      hovered = null;
      const label = document.getElementById('graphHoverLabel');
      if (label) label.style.display = 'none';
    }

    function assignPos(index, total) {
      const phi = Math.acos(1 - 2 * ((index + 0.5) / total));
      const theta = Math.PI * (1 + Math.sqrt(5)) * index;
      const radius = 2.2 + (index % 5) * 0.18;
      return new THREE.Vector3(
        Math.cos(theta) * Math.sin(phi) * radius,
        Math.sin(theta) * Math.sin(phi) * radius * 0.7,
        Math.cos(phi) * radius
      );
    }

    function setData(findings, attackPaths) {
      clearGraph();
      const capped = (findings || []).slice(0, 64);
      if (!capped.length) return;

      const positions = capped.map((_, idx) => assignPos(idx, capped.length));

      capped.forEach((finding, idx) => {
        const sev = finding?.severity || 'None';
        const score = Math.max(0.2, Math.min(10, Number(finding?.cvss_score || 0)));
        const radius = 0.09 + score * 0.012;

        const mesh = new THREE.Mesh(
          new THREE.SphereGeometry(radius, 18, 18),
          new THREE.MeshStandardMaterial({
            color: severityColor[sev] || 0x4fa5ff,
            emissive: 0x000000,
            emissiveIntensity: 0.5,
            roughness: 0.4,
            metalness: 0.2,
          })
        );

        mesh.position.copy(positions[idx]);
        mesh.userData.finding = finding;
        mesh.userData.baseScale = 1;
        mesh.userData.phase = Array.isArray(finding?.mitre_kill_chain) ? finding.mitre_kill_chain[0] || '' : '';
        nodesGroup.add(mesh);
        nodeMeshes.push(mesh);

        if (mesh.userData.phase) {
          if (!phaseLookup.has(mesh.userData.phase)) phaseLookup.set(mesh.userData.phase, []);
          phaseLookup.get(mesh.userData.phase).push(mesh);
        }
      });

      for (let i = 0; i < positions.length - 1; i++) {
        const curve = new THREE.CatmullRomCurve3([
          positions[i],
          positions[i].clone().add(positions[i + 1]).multiplyScalar(0.5).multiplyScalar(1.05),
          positions[i + 1],
        ]);
        const pts = curve.getPoints(12);
        const geom = new THREE.BufferGeometry().setFromPoints(pts);
        const line = new THREE.Line(geom, new THREE.LineBasicMaterial({ color: 0x2c79a9, transparent: true, opacity: 0.55 }));
        edgesGroup.add(line);
      }

      if (Array.isArray(attackPaths) && attackPaths.length) {
        attackPaths.forEach(path => {
          const phase = path.phase;
          const list = phaseLookup.get(phase) || [];
          list.forEach(mesh => {
            mesh.material.emissive = new THREE.Color(0x11263c);
          });
        });
      }
    }

    function highlightPhase(phase) {
      focusedPhase = phase || '';
      nodeMeshes.forEach(mesh => {
        const active = focusedPhase && mesh.userData.phase === focusedPhase;
        mesh.material.emissive = active ? new THREE.Color(0x1d6ea0) : new THREE.Color(0x000000);
      });
    }

    function onPointerMove(event) {
      const rect = rt.host.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    }

    rt.host.addEventListener('pointermove', onPointerMove);
    rt.host.addEventListener('pointerleave', () => {
      pointer.set(2, 2);
      if (hovered) {
        hovered.scale.setScalar(hovered.userData.baseScale || 1);
        hovered = null;
      }
      const label = document.getElementById('graphHoverLabel');
      if (label) label.style.display = 'none';
    });

    rt.animate = (delta) => {
      root.rotation.y += delta * 0.12;

      nodeMeshes.forEach((mesh, idx) => {
        const breathe = 1 + Math.sin(performance.now() * 0.0025 + idx * 0.6) * 0.05;
        const base = focusedPhase && mesh.userData.phase === focusedPhase ? 1.2 : 1;
        mesh.scale.setScalar(breathe * base);
      });

      raycaster.setFromCamera(pointer, rt.camera);
      const hits = raycaster.intersectObjects(nodeMeshes, false);
      const label = document.getElementById('graphHoverLabel');

      if (hits.length) {
        const hit = hits[0].object;
        if (hovered && hovered !== hit) {
          hovered.scale.setScalar(hovered.userData.baseScale || 1);
        }
        hovered = hit;
        hit.scale.setScalar(1.35);

        if (label) {
          const finding = hit.userData.finding || {};
          label.style.display = '';
          label.innerHTML = `<strong>${escHtml(finding.severity || 'None')}</strong> · ${escHtml(finding.type || finding.module || 'Finding')}<br>${escHtml((finding.detail || finding.payload || '').slice(0, 120))}`;
        }
      } else if (hovered) {
        hovered.scale.setScalar(hovered.userData.baseScale || 1);
        hovered = null;
        if (label) label.style.display = 'none';
      }
    };

    rt.api = {
      setData,
      highlightPhase,
    };
  }, 'Attack graph unavailable.');

  if (!runtime || !runtime.api) {
    return {
      setData: () => {},
      highlightPhase: () => {},
    };
  }
  return runtime.api;
}

function initMitreMatrixScene(containerId, cloudId) {
  if (REDUCED_MOTION) {
    const host = document.getElementById(containerId);
    if (host) host.innerHTML = '<div class="mapping-empty">Reduced motion enabled · static matrix mode.</div>';
    return {
      setCoverage: () => {},
      setSelectedTactic: () => {},
    };
  }

  const runtime = mountThreeRuntime(containerId, (rt) => {
    const ambient = new THREE.AmbientLight(0x9bc4ea, 0.52);
    const key = new THREE.PointLight(0x00d4ff, 1.25, 40);
    key.position.set(6, 8, 6);
    rt.scene.add(ambient, key);

    rt.camera.position.set(0, 4.4, 8.2);
    if (rt.controls) {
      rt.controls.autoRotate = true;
      rt.controls.autoRotateSpeed = 0.28;
      rt.controls.minDistance = 4;
      rt.controls.maxDistance = 14;
      rt.controls.maxPolarAngle = Math.PI / 2.05;
    }

    const barsGroup = new THREE.Group();
    const particlesGroup = new THREE.Group();
    rt.scene.add(barsGroup);
    rt.scene.add(particlesGroup);

    const base = new THREE.Mesh(
      new THREE.CylinderGeometry(4.5, 4.5, 0.18, 40),
      new THREE.MeshStandardMaterial({ color: 0x0f1c2b, metalness: 0.3, roughness: 0.74 })
    );
    base.position.y = -0.15;
    rt.scene.add(base);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2(2, 2);

    let bars = [];
    let selected = '';
    let onSelect = null;

    function colorForCoverage(pct) {
      if (pct >= 60) return 0xff1f4b;
      if (pct >= 20) return 0xf5a623;
      if (pct > 0) return 0xff6b35;
      return 0x3a4d62;
    }

    function clearBars() {
      bars.forEach(bar => {
        bar.geometry.dispose();
        bar.material.dispose();
      });
      barsGroup.clear();
      particlesGroup.clear();
      bars = [];
    }

    function setCoverage(tactics) {
      clearBars();
      const data = Array.isArray(tactics) ? tactics : [];
      if (!data.length) return;

      const spread = Math.PI * 0.92;
      const start = -spread / 2;
      const radius = 3.35;

      data.forEach((tactic, idx) => {
        const pct = Number(tactic.coverage_pct || 0);
        const height = 0.28 + (pct / 100) * 2.5;
        const angle = start + (idx / Math.max(1, data.length - 1)) * spread;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;

        const mat = new THREE.MeshStandardMaterial({
          color: colorForCoverage(pct),
          emissive: 0x000000,
          roughness: 0.42,
          metalness: 0.22,
        });

        const bar = new THREE.Mesh(new THREE.BoxGeometry(0.35, height, 0.35), mat);
        bar.position.set(x, height / 2, z);
        bar.lookAt(0, height / 2, 0);
        bar.userData = {
          tactic: tactic.tactic,
          pct,
          baseColor: colorForCoverage(pct),
        };
        barsGroup.add(bar);
        bars.push(bar);

        if (pct > 0) {
          const pCount = Math.min(22, Math.max(4, Math.round(pct / 5)));
          const geom = new THREE.BufferGeometry();
          const arr = new Float32Array(pCount * 3);
          for (let i = 0; i < pCount; i++) {
            arr[i * 3] = x + (Math.random() - 0.5) * 0.2;
            arr[i * 3 + 1] = height + Math.random() * 0.5;
            arr[i * 3 + 2] = z + (Math.random() - 0.5) * 0.2;
          }
          geom.setAttribute('position', new THREE.BufferAttribute(arr, 3));
          const points = new THREE.Points(geom, new THREE.PointsMaterial({ color: 0x00d4ff, size: 0.03, transparent: true, opacity: 0.75 }));
          points.userData = { drift: 0.12 + Math.random() * 0.1 };
          particlesGroup.add(points);
        }
      });

      setSelectedTactic(selected);
    }

    function setSelectedTactic(tactic) {
      selected = tactic || '';
      bars.forEach(bar => {
        const active = selected && bar.userData.tactic === selected;
        bar.material.emissive = active ? new THREE.Color(0x1e7fb2) : new THREE.Color(0x000000);
        bar.scale.set(active ? 1.14 : 1, active ? 1.05 : 1, active ? 1.14 : 1);
      });
    }

    function onPointerMove(event) {
      const rect = rt.host.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    }

    function onClick() {
      raycaster.setFromCamera(pointer, rt.camera);
      const hit = raycaster.intersectObjects(bars, false)[0];
      if (!hit) return;
      const tactic = hit.object.userData.tactic;
      const next = selected === tactic ? '' : tactic;
      setSelectedTactic(next);
      if (typeof onSelect === 'function') onSelect(next);
    }

    rt.host.addEventListener('pointermove', onPointerMove);
    rt.host.addEventListener('click', onClick);

    rt.animate = (delta) => {
      barsGroup.rotation.y += delta * 0.06;
      particlesGroup.rotation.y += delta * 0.04;
      particlesGroup.children.forEach(points => {
        const pos = points.geometry.getAttribute('position');
        for (let i = 0; i < pos.count; i++) {
          pos.array[i * 3 + 1] += points.userData.drift * delta;
          if (pos.array[i * 3 + 1] > 4) pos.array[i * 3 + 1] = 0.45;
        }
        pos.needsUpdate = true;
      });
    };

    rt.api = {
      setCoverage,
      setSelectedTactic,
      setOnSelect: (cb) => { onSelect = cb; },
      cloudId,
    };
  }, 'MITRE matrix unavailable.');

  if (!runtime || !runtime.api) {
    return {
      setCoverage: () => {},
      setSelectedTactic: () => {},
      setOnSelect: () => {},
    };
  }

  runtime.api.setOnSelect((tactic) => {
    mitreBreakdownState.selectedTactic = tactic;
    const sel = document.getElementById('mitreFilterTactic');
    if (sel) sel.value = tactic;
    _highlightMatrixFilter(tactic);
    _applyMitreBreakdownFilters();
  });

  return runtime.api;
}

function estimateTargetSignal(rawTarget) {
  if (!rawTarget) {
    return { lat: 12, lng: 72, label: 'Awaiting target intelligence...' };
  }

  let host = rawTarget;
  try {
    if (!/^https?:\/\//i.test(host)) host = 'http://' + host;
    host = new URL(host).hostname || host;
  } catch {
    host = rawTarget;
  }

  const hash = _simpleHash(host.toLowerCase());
  const lat = ((hash % 18000) / 100) - 90;
  const lng = ((((hash / 18000) | 0) % 36000) / 100) - 180;
  const tld = host.split('.').pop() || 'net';
  const region = {
    com: 'Global Commercial Zone',
    org: 'Public Sector Mesh',
    edu: 'Academic Sector',
    io: 'Cloud Native Sector',
    gov: 'Government Sector',
  }[tld] || 'Signal Sector';

  return {
    lat,
    lng,
    label: `${host} · ${region} · lat ${lat.toFixed(2)} / lng ${lng.toFixed(2)}`,
  };
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds || 0)));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}

function escHtml(str) {
  if (str == null) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function sanitizeAiHtml(html) {
  if (!html) return '';
  let clean = html.replace(/<\s*\/?\s*(script|iframe|object|embed|form|style|link|meta|base)\b[^>]*>/gi, '');
  clean = clean.replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  clean = clean.replace(/(href|src)\s*=\s*(?:"|')javascript:[^"']*(?:"|')/gi, '$1=""');
  return clean;
}
