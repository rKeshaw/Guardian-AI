const MONITOR_PHASES = [
  "reconnaissance",
  "vulnerability_analysis",
  "hypothesis_seeding",
  "payload_generation",
  "active_penetration",
  "graph_exploration",
  "active_confirmation",
  "reporting",
];

const monitorState = {
  sessionId: null,
  findingsById: {},
  stats: {
    hypotheses_total: 0,
    hypotheses_explored: 0,
    findings: 0,
    dead_ends: 0,
    requests_made: 0,
    payloads_generated: 0,
    confirmed_findings: 0,
  },
  fallbackTimers: [],
  reconnectTimer: null,
  ws: null,
};

window.initMonitorView = async function initMonitorView(params = {}) {
  const sessionId = params.sessionId || state.sessions?.[0]?.id;
  const root = document.getElementById("view-monitor");
  if (!root) return;
  if (!sessionId) {
    root.innerHTML = '<div class="card">No session selected. Start a new scan from NEW SCAN.</div>';
    return;
  }
  monitorState.sessionId = sessionId;
  monitorState.findingsById = {};
  monitorState.stats = { hypotheses_total: 0, hypotheses_explored: 0, findings: 0, dead_ends: 0, requests_made: 0, payloads_generated: 0, confirmed_findings: 0 };
  teardownMonitor();

  root.innerHTML = `
    <div class="monitor-header" style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <div>
        <div style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)">SESSION <span id="monitor-session">${truncate(sessionId, 24)}</span></div>
        <div id="monitor-target" style="font-size:13px;color:var(--text-primary)">Loading target…</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <span id="monitor-status-badge" class="badge b-initializing">INITIALIZING</span>
        <button id="monitor-stop-btn" class="btn">Stop Scan</button>
      </div>
    </div>

    <div id="phase-timeline" class="phase-timeline"></div>

    <div class="monitor-main">
      <div>
        <div class="card">
          <h3 style="margin-top:0">Event Log Feed <span id="monitor-last-seen" class="tiny">(waiting)</span></h3>
          <div id="monitor-log-feed" class="log-feed"></div>
        </div>
      </div>
      <div>
        <div class="card">
          <h3 style="margin-top:0">Live Stats</h3>
          <div class="tiny" style="margin-bottom:4px">Token Budget <span id="token-budget-label">0 / 0</span></div>
          <div class="token-bar-wrap"><div id="token-budget-bar" class="token-bar"></div></div>
          <div class="stats-grid" style="margin-top:10px;">
            <div class="mini-stat">Hypotheses Total<div id="st-hyp-total" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Explored<div id="st-hyp-exp" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Findings<div id="st-findings" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Dead Ends<div id="st-dead" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Requests Made<div id="st-req" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Payloads Generated<div id="st-payload" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Confirmed Findings<div id="st-confirmed" class="stat-value" style="font-size:1rem">0</div></div>
            <div class="mini-stat">Current Hypothesis<div id="st-current" class="tiny">-</div></div>
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:12px;">
      <h3 style="margin-top:0">Preliminary Findings</h3>
      <div class="table-wrap findings-table">
        <table>
          <thead><tr><th>Severity</th><th>OWASP</th><th>Hypothesis</th><th>Injection Point</th><th>Confidence</th><th>Status</th></tr></thead>
          <tbody id="monitor-findings-tbody"></tbody>
        </table>
      </div>
    </div>
  `;

  renderPhaseTimeline();
  bindMonitorActions();
  await loadMonitorSnapshot(sessionId);
  connectWebSocket(sessionId);
};

function truncate(v, n = 50) { return (v || "").length > n ? `${v.slice(0, n)}…` : (v || ""); }

function renderPhaseTimeline() {
  const root = document.getElementById("phase-timeline");
  if (!root) return;
  root.innerHTML = "";
  MONITOR_PHASES.forEach((p, i) => {
    const block = document.createElement("div");
    block.className = "phase-block pending";
    block.id = `phase-${p}`;
    block.innerHTML = `<div class="tiny" style="text-transform:uppercase">${p.replace(/_/g, ' ').replace(/\b\w/g,m=>m.toUpperCase()).split(' ').map(w=>w.slice(0,4)).join(' ')}</div><div class="tiny" id="phase-dur-${p}">-</div>`;
    root.appendChild(block);
    if (i < MONITOR_PHASES.length - 1) {
      const conn = document.createElement("div");
      conn.className = "phase-connector";
      root.appendChild(conn);
    }
  });
}

function bindMonitorActions() {
  const stopBtn = document.getElementById("monitor-stop-btn");
  if (stopBtn) {
    stopBtn.onclick = async () => {
      if (!confirm("Stop this scan?")) return;
      try {
        await apiFetch(`/api/v1/scan/${monitorState.sessionId}`, { method: "DELETE" });
        appendLog({ event: "scan_error", error: "Scan stopped by operator" });
        setStatusBadge("ERROR");
      } catch (e) {
        appendLog({ event: "phase_error", data: { error: `Stop failed: ${e.message}` } });
      }
    };
  }
}

async function loadMonitorSnapshot(sessionId) {
  try {
    const status = await apiFetch(`/api/v1/scan/${sessionId}/status`);
    setStatusBadge(status.status || "INITIALIZING");
    const target = state.sessions.find((s) => s.id === sessionId)?.target || "unknown";
    document.getElementById("monitor-target").textContent = target;

    const agentStatus = status.agent_status || {};
    MONITOR_PHASES.forEach((p) => {
      const entry = agentStatus[p] || {};
      if (entry.status === "running") updatePhaseStatus(p, "running");
      else if (entry.status === "completed") updatePhaseStatus(p, entry.skipped ? "skipped" : "completed", null);
      else if (entry.status === "failed") updatePhaseStatus(p, "failed");
      else updatePhaseStatus(p, "pending");
    });

    const preview = status.results || {};
    monitorState.stats.payloads_generated = Number(preview.payload_generation?.payload_count || 0);
    monitorState.stats.confirmed_findings = Number(preview.active_confirmation?.confirmed_count || 0);
    monitorState.stats.findings = Number(preview.graph_exploration?.finding_count || 0);
    updateStatsUI();
  } catch (e) {
    appendLog({ event: "phase_error", data: { error: `snapshot failed: ${e.message}` } });
  }
}

function connectWebSocket(sessionId) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/ws/scan/${sessionId}?api_key=${encodeURIComponent(state.apiKey || "")}`;
  try {
    const ws = new WebSocket(url);
    ws.onmessage = (e) => {
      try { handleEvent(JSON.parse(e.data)); } catch {}
    };
    ws.onclose = () => scheduleReconnect(sessionId);
    ws.onerror = () => fallbackToPolling(sessionId);
    monitorState.ws = ws;
    state.activeWebSockets[sessionId] = ws;
  } catch {
    fallbackToPolling(sessionId);
  }
}

function scheduleReconnect(sessionId) {
  if (monitorState.reconnectTimer) clearTimeout(monitorState.reconnectTimer);
  monitorState.reconnectTimer = setTimeout(() => connectWebSocket(sessionId), 3000);
}

function fallbackToPolling(sessionId) {
  teardownTimers();
  const t1 = setInterval(async () => {
    try {
      const status = await apiFetch(`/api/v1/scan/${sessionId}/status`);
      setStatusBadge(status.status || "INITIALIZING");
      const a = status.agent_status || {};
      MONITOR_PHASES.forEach((p) => {
        const s = a[p]?.status || "pending";
        const mapped = s === "completed" ? (a[p]?.skipped ? "skipped" : "completed") : s;
        updatePhaseStatus(p, mapped);
      });
      if (String(status.status).toLowerCase() === "completed" || String(status.status).toLowerCase() === "error") finalizeMonitor();
    } catch {}
  }, 3000);

  const t2 = setInterval(async () => {
    try {
      const graph = await apiFetch(`/api/v1/scan/${sessionId}/graph`);
      const findings = (graph.nodes || []).filter((n) => n.type === "finding");
      findings.forEach((f) => {
        if (!monitorState.findingsById[f.id]) addFindingRow({ id: f.id, owasp: "", hypothesis: f.id, confidence: Math.round((f.confidence || 0) * 100) });
      });
    } catch {}
  }, 10000);

  monitorState.fallbackTimers.push(t1, t2);
}

function teardownTimers() {
  while (monitorState.fallbackTimers.length) clearInterval(monitorState.fallbackTimers.pop());
}

function teardownMonitor() {
  teardownTimers();
  if (monitorState.reconnectTimer) clearTimeout(monitorState.reconnectTimer);
  if (monitorState.ws) {
    try { monitorState.ws.close(); } catch {}
    monitorState.ws = null;
  }
}

function now() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
}

function appendLog(event) {
  const feed = document.getElementById("monitor-log-feed");
  if (!feed) return;
  const line = document.createElement("div");
  let cls = "";
  if (event.event === "finding_added") cls = "finding";
  else if (event.event?.includes("error")) cls = "error";
  else if (event.event === "phase_complete") cls = "phase";
  else if (event.event === "hypothesis_exploring") cls = "hypothesis";
  else if (event.event === "hypothesis_dead") cls = "dead";
  else if (event.event === "ledger_update") cls = "ledger";
  line.className = `log-line ${cls}`;

  const msg = summarizeEvent(event);
  line.textContent = `[${now()}] ${String(event.event || 'event').toUpperCase()} | ${msg}`;
  feed.appendChild(line);
  while (feed.children.length > 500) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

function summarizeEvent(event) {
  if (event.event === "phase_start") return `phase=${event.phase}`;
  if (event.event === "phase_complete") return `phase=${event.phase} duration=${event?.data?.duration_s ?? '-'}s`;
  if (event.event === "phase_error") return `${event.phase}: ${event?.data?.error || 'unknown error'}`;
  if (event.event === "finding_added") return `${event?.data?.owasp || ''} ${truncate(event?.data?.hypothesis || '', 100)}`;
  if (event.event === "hypothesis_exploring") return `${event?.data?.owasp || ''} ${truncate(event?.data?.hypothesis || '', 100)}`;
  if (event.event === "ledger_update") return `used=${event?.data?.used || 0} total=${event?.data?.total || 0}`;
  if (event.event === "scan_complete") return "scan finished";
  if (event.event === "heartbeat") return "heartbeat";
  return JSON.stringify(event?.data || event).slice(0, 140);
}

function updatePhaseStatus(phase, status, duration) {
  const block = document.getElementById(`phase-${phase}`);
  if (!block) return;
  block.className = `phase-block ${status || 'pending'}`;
  const d = document.getElementById(`phase-dur-${phase}`);
  if (d && duration != null) d.textContent = `${duration}s`;
}

function setStatusBadge(status) {
  const el = document.getElementById("monitor-status-badge");
  if (!el) return;
  const s = String(status || "").toLowerCase();
  el.className = `badge ${s === 'running' ? 'b-running' : s === 'completed' ? 'b-completed' : s === 'error' ? 'b-error' : 'b-initializing'}`;
  el.textContent = String(status || "INITIALIZING").toUpperCase();
}

function updateStats(key, delta = 1) {
  monitorState.stats[key] = (monitorState.stats[key] || 0) + delta;
  updateStatsUI();
}

function updateCurrentHypothesis(data) {
  const el = document.getElementById("st-current");
  if (el) el.textContent = truncate(data?.hypothesis || '-', 70);
}

function updateTokenBudget(data = {}) {
  const used = Number(data.used || 0);
  const total = Number(data.total || 0);
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const bar = document.getElementById("token-budget-bar");
  const lbl = document.getElementById("token-budget-label");
  if (bar) bar.style.width = `${pct.toFixed(1)}%`;
  if (lbl) lbl.textContent = `${used} / ${total}`;
}

function updateStatsUI() {
  const s = monitorState.stats;
  const map = {
    "st-hyp-total": s.hypotheses_total,
    "st-hyp-exp": s.hypotheses_explored,
    "st-findings": s.findings,
    "st-dead": s.dead_ends,
    "st-req": s.requests_made,
    "st-payload": s.payloads_generated,
    "st-confirmed": s.confirmed_findings,
  };
  Object.entries(map).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val || 0);
  });
}

function addFindingRow(data) {
  if (!data || !data.id || monitorState.findingsById[data.id]) return;
  monitorState.findingsById[data.id] = data;
  const tbody = document.getElementById("monitor-findings-tbody");
  if (!tbody) return;
  const tr = document.createElement("tr");
  const sev = String(data.severity || "medium").toLowerCase();
  tr.innerHTML = `
    <td><span class="badge badge-${sev}">${String(data.severity || "Medium")}</span></td>
    <td><span class="badge badge-owasp">${data.owasp || "-"}</span></td>
    <td title="${data.hypothesis || ""}">${truncate(data.hypothesis || "", 90)}</td>
    <td>${truncate(data.injection_point || "-", 38)}</td>
    <td>${Math.round((Number(data.confidence || 0) <= 1 ? Number(data.confidence || 0) * 100 : Number(data.confidence || 0)))}%</td>
    <td>${data.status || "discovered"}</td>`;
  tr.onclick = () => setDetail(`Finding ${data.id}\n${data.hypothesis || ''}`);
  tbody.appendChild(tr);
}

function finalizeMonitor() {
  teardownMonitor();
  appendLog({ event: "scan_complete", data: {} });
}

function handleEvent(event) {
  appendLog(event);
  const ev = event.event;
  if (ev === "phase_start") updatePhaseStatus(event.phase, "running");
  else if (ev === "phase_complete") updatePhaseStatus(event.phase, event?.data?.skipped ? "skipped" : "completed", event?.data?.duration_s);
  else if (ev === "phase_error") updatePhaseStatus(event.phase, "failed");
  else if (ev === "finding_added") {
    addFindingRow(event.data || {});
    updateStats("findings", 1);
  } else if (ev === "hypothesis_exploring") {
    updateStats("hypotheses_explored", 1);
    updateCurrentHypothesis(event.data || {});
  } else if (ev === "hypothesis_dead") {
    updateStats("dead_ends", 1);
  } else if (ev === "ledger_update") {
    updateTokenBudget(event.data || {});
  } else if (ev === "scan_complete") {
    setStatusBadge("COMPLETED");
    finalizeMonitor();
  } else if (ev === "scan_error") {
    setStatusBadge("ERROR");
    finalizeMonitor();
  } else if (ev === "heartbeat") {
    const x = document.getElementById("monitor-last-seen");
    if (x) x.textContent = `(last heartbeat ${now()})`;
  }
}

