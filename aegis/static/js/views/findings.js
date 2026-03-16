const OWASP_CATEGORIES = [
  "A01:2023", "A02:2023", "A03:2023", "A04:2023", "A05:2023",
  "A06:2023", "A07:2023", "A08:2023", "A09:2023", "A10:2023",
];

const findingsState = {
  all: [],
  filtered: [],
  selectedIds: new Set(),
  filters: {
    owasp: new Set(OWASP_CATEGORIES),
    severity: new Set(["critical", "high", "medium", "low"]),
    httpConfirmedOnly: false,
    deterministicOnly: false,
    minConfidence: 0,
    sortBy: "severity",
  },
  activeSessionId: null,
};

window.initFindingsView = async function initFindingsView(params = {}) {
  const root = document.getElementById("view-findings");
  if (!root) return;

  findingsState.activeSessionId = params.sessionId || null;
  root.innerHTML = `<div class="findings-header-row"><h2 class="panel-title">Findings</h2><div id="findings-session-picker"></div></div><div id="findings-root"></div>`;

  if (!params.sessionId) renderSessionPicker();
  await loadFindingsData(params.sessionId);
  renderFindingsView();
};

function renderSessionPicker() {
  const picker = document.getElementById("findings-session-picker");
  if (!picker) return;
  const opts = state.sessions.map((s) => `<option value="${s.id}">${truncate(s.target || s.id, 40)} • ${String(s.status || "unknown").toUpperCase()} • ${new Date(s.addedAt || Date.now()).toLocaleDateString()}</option>`).join("");
  picker.innerHTML = `<select id="findings-session-select" class="input"><option value="">All sessions</option>${opts}</select>`;
  const sel = document.getElementById("findings-session-select");
  if (sel) {
    sel.value = findingsState.activeSessionId || "";
    sel.onchange = () => showView("findings", { sessionId: sel.value || undefined });
  }
}

async function loadFindingsData(sessionId) {
  const sessions = sessionId ? [{ id: sessionId }] : (state.sessions || []);
  const out = [];

  for (const s of sessions) {
    try {
      const res = await apiFetch(`/api/v1/scan/${s.id}/results`);
      const report = extractReporting(res.results || []);
      const technical = report.technical_findings || [];
      const deterministic = res.results.find((r) => r.agent_name === "orchestrator")?.results?.deterministic_findings || [];

      technical.forEach((f, idx) => {
        out.push(normalizeFinding(f, s.id, idx));
      });
      deterministic.forEach((d, idx) => {
        out.push(normalizeFinding({
          vulnerability_name: d.vulnerability_name,
          owasp_category: d.owasp_category,
          cwe: d.cwe,
          risk_level: d.risk_level,
          description: d.evidence,
          proof_of_concept: `Deterministic check: ${d.evidence}`,
          remediation: d.remediation,
          deterministic: true,
          cvss_score: d.cvss_score || 0,
          cvss_vector: d.cvss_vector || "",
        }, s.id, `d-${idx}`));
      });
    } catch {
      // ignore missing/in-progress sessions
    }
  }

  findingsState.all = out;
}

function extractReporting(results) {
  for (const row of results || []) {
    if (row.agent_name === "reporting") return row.results || {};
  }
  return {};
}

function normalizeFinding(f, sessionId, idx) {
  const score = Number(f.cvss_score || 0);
  const severity = String(f.risk_level || (score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : "Low"));
  const conf = Number(f.confidence || 0);
  const httpConfirmed = !!f?.http_confirmation?.confirmed;
  return {
    ...f,
    id: `${sessionId}-${idx}`,
    sessionId,
    confidence: conf <= 1 ? Math.round(conf * 100) : Math.round(conf),
    severity,
    severityKey: severity.toLowerCase(),
    httpConfirmed,
    deterministic: !!f.deterministic,
    owasp: f.owasp_category || "Unknown",
    cwe: f.cwe || "CWE-unknown",
    title: f.vulnerability_name || "Unnamed finding",
  };
}

function renderFindingsView() {
  const root = document.getElementById("findings-root");
  if (!root) return;

  if (!findingsState.all.length) {
    root.innerHTML = `<div class="card">No findings loaded. Select a completed scan.</div>`;
    return;
  }

  applyFilters();
  root.innerHTML = `${renderFilterBar()}<div id="finding-cards">${findingsState.filtered.map(renderCard).join("")}</div>`;
  bindFindingsEvents();
}

function renderFilterBar() {
  const severity = ["critical", "high", "medium", "low"].map((x) => `<button class="pill ${findingsState.filters.severity.has(x) ? "active" : ""}" data-sev="${x}">${x}</button>`).join("");
  const owasp = OWASP_CATEGORIES.map((x) => `<button class="pill ${findingsState.filters.owasp.has(x) ? "active" : ""}" data-owasp="${x}">${x}</button>`).join("");
  return `
    <div class="card sticky-filter">
      <div><strong>OWASP</strong> ${owasp}</div>
      <div style="margin-top:8px"><strong>Severity</strong> ${severity}</div>
      <div style="margin-top:8px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <label><input type="checkbox" id="flt-http" ${findingsState.filters.httpConfirmedOnly ? "checked" : ""}/> HTTP Confirmed Only</label>
        <label><input type="checkbox" id="flt-det" ${findingsState.filters.deterministicOnly ? "checked" : ""}/> Deterministic Only</label>
        <label>Confidence ≥ <input type="range" id="flt-conf" min="0" max="100" value="${findingsState.filters.minConfidence}"/> <span id="flt-conf-label">${findingsState.filters.minConfidence}</span>%</label>
        <label>Sort by <select id="flt-sort"><option value="severity">Severity</option><option value="cvss">CVSS Score</option><option value="confidence">Confidence</option><option value="owasp">OWASP</option></select></label>
        <a href="#" id="flt-clear">Clear Filters</a>
      </div>
      <div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center;">
        <div class="tiny">Showing ${findingsState.filtered.length} of ${findingsState.all.length} findings</div>
        <div>
          <select id="export-type" class="input" style="width:auto;display:inline-block"><option value="json">JSON</option><option value="markdown">Markdown</option></select>
          <button class="btn" id="export-selected">Export Selected (${findingsState.selectedIds.size})</button>
        </div>
      </div>
    </div>`;
}

function renderCard(f) {
  const conf = Math.min(100, Math.max(0, Number(f.confidence || 0)));
  const cvss = parseCvss(f.cvss_vector || "");
  const httpBanner = f.httpConfirmed
    ? `<div class="banner success">HTTP CONFIRMED — differential indicators: ${(f.http_confirmation?.indicators || []).join(", ") || "n/a"}</div>`
    : `<div class="banner warn">LLM-reported — active HTTP replay did not produce differential indicators</div>`;
  const detBanner = f.deterministic ? `<div class="banner info">DETERMINISTIC FINDING — detected without LLM inference</div>` : "";

  return `<article class="finding-card" data-id="${f.id}">
    <div class="finding-top">
      <label><input type="checkbox" class="finding-select" data-id="${f.id}" ${findingsState.selectedIds.has(f.id) ? "checked" : ""}/></label>
      <span class="badge badge-${f.severityKey}">${f.severity}</span>
      <span class="badge badge-owasp">${f.owasp}</span>
      <span class="badge badge-owasp">${f.cwe}</span>
      ${f.httpConfirmed ? '<span class="badge b-completed">HTTP CONFIRMED</span>' : ""}
      <div class="confidence-mini"><div style="width:${conf}%"></div></div>
    </div>
    <h3>${escapeHtml(f.title)}</h3>
    <div class="tiny" style="font-family:var(--font-mono)">${escapeHtml(f.injection_point?.url || "-")} :: ${escapeHtml(f.injection_point?.parameter || "-")}</div>
    <details>
      <summary>Details</summary>
      <div class="cvss-grid">
        <div class="cvss-score">${Number(f.cvss_score || 0).toFixed(1)}</div>
        <code>${escapeHtml(f.cvss_vector || "")}</code>
      </div>
      <div class="metric-boxes">${["AV", "AC", "PR", "UI", "S", "C", "I", "A"].map((m) => `<span class="metric" title="${m}">${m}:${cvss[m] || "-"}</span>`).join("")}</div>
      <p>${escapeHtml(f.description || "")}</p>
      ${httpBanner}
      <div><strong>Proof of Concept</strong><button class="btn copy-btn" data-copy="${encodeURIComponent(f.proof_of_concept || "")}">Copy</button><pre>${escapeHtml(f.proof_of_concept || "")}</pre></div>
      <div><strong>Evidence</strong> <span class="badge badge-owasp">${escapeHtml(f.proof_type || "unknown")}</span></div>
      <div><strong>Extracted Data</strong><pre>${escapeHtml(f.extracted_data || "")}</pre></div>
      <div><strong>Payload</strong><button class="btn copy-btn" data-copy="${encodeURIComponent(f.payload_used || "")}">Copy</button><pre>${escapeHtml(f.payload_used || "")}</pre></div>
      <p><strong>Remediation:</strong> ${escapeHtml(f.remediation || "")}</p>
      ${detBanner}
    </details>
  </article>`;
}

function parseCvss(vector) {
  const parts = String(vector || "").split("/");
  const out = {};
  for (const part of parts) {
    if (part.includes(":")) {
      const [k, v] = part.split(":");
      if (k.length <= 3) out[k] = v;
    }
  }
  return out;
}

function applyFilters() {
  const f = findingsState.filters;
  findingsState.filtered = findingsState.all.filter((row) => {
    if (!f.owasp.has(row.owasp)) return false;
    if (!f.severity.has(row.severityKey)) return false;
    if (f.httpConfirmedOnly && !row.httpConfirmed) return false;
    if (f.deterministicOnly && !row.deterministic) return false;
    if (Number(row.confidence || 0) < f.minConfidence) return false;
    return true;
  });

  const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const sorters = {
    severity: (a, b) => sevRank[b.severityKey] - sevRank[a.severityKey],
    cvss: (a, b) => Number(b.cvss_score || 0) - Number(a.cvss_score || 0),
    confidence: (a, b) => Number(b.confidence || 0) - Number(a.confidence || 0),
    owasp: (a, b) => String(a.owasp).localeCompare(String(b.owasp)),
  };
  findingsState.filtered.sort(sorters[f.sortBy] || sorters.severity);
}

function bindFindingsEvents() {
  document.querySelectorAll("[data-owasp]").forEach((el) => {
    el.onclick = () => {
      const key = el.dataset.owasp;
      if (findingsState.filters.owasp.has(key)) findingsState.filters.owasp.delete(key);
      else findingsState.filters.owasp.add(key);
      renderFindingsView();
    };
  });
  document.querySelectorAll("[data-sev]").forEach((el) => {
    el.onclick = () => {
      const key = el.dataset.sev;
      if (findingsState.filters.severity.has(key)) findingsState.filters.severity.delete(key);
      else findingsState.filters.severity.add(key);
      renderFindingsView();
    };
  });

  const http = document.getElementById("flt-http");
  if (http) http.onchange = () => { findingsState.filters.httpConfirmedOnly = http.checked; renderFindingsView(); };
  const det = document.getElementById("flt-det");
  if (det) det.onchange = () => { findingsState.filters.deterministicOnly = det.checked; renderFindingsView(); };
  const conf = document.getElementById("flt-conf");
  if (conf) conf.oninput = () => {
    findingsState.filters.minConfidence = Number(conf.value || 0);
    const lbl = document.getElementById("flt-conf-label");
    if (lbl) lbl.textContent = String(findingsState.filters.minConfidence);
    renderFindingsView();
  };
  const sort = document.getElementById("flt-sort");
  if (sort) {
    sort.value = findingsState.filters.sortBy;
    sort.onchange = () => { findingsState.filters.sortBy = sort.value; renderFindingsView(); };
  }
  const clear = document.getElementById("flt-clear");
  if (clear) clear.onclick = (e) => {
    e.preventDefault();
    findingsState.filters = {
      owasp: new Set(OWASP_CATEGORIES),
      severity: new Set(["critical", "high", "medium", "low"]),
      httpConfirmedOnly: false,
      deterministicOnly: false,
      minConfidence: 0,
      sortBy: "severity",
    };
    renderFindingsView();
  };

  document.querySelectorAll(".finding-select").forEach((el) => {
    el.onchange = () => {
      if (el.checked) findingsState.selectedIds.add(el.dataset.id);
      else findingsState.selectedIds.delete(el.dataset.id);
      const btn = document.getElementById("export-selected");
      if (btn) btn.textContent = `Export Selected (${findingsState.selectedIds.size})`;
    };
  });

  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.onclick = async () => {
      const value = decodeURIComponent(btn.dataset.copy || "");
      await navigator.clipboard.writeText(value);
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy"; }, 1000);
    };
  });

  document.querySelectorAll(".finding-card").forEach((card) => {
    card.onclick = (e) => {
      if (e.target.closest("button") || e.target.closest("input") || e.target.closest("summary")) return;
      const id = card.dataset.id;
      const finding = findingsState.filtered.find((x) => x.id === id);
      if (!finding) return;
      openRightPanel("Finding Detail", `<h4>${escapeHtml(finding.title)}</h4><p>${escapeHtml(finding.description || "")}</p><code>${escapeHtml(finding.cvss_vector || "")}</code>`);
    };
  });

  const exportBtn = document.getElementById("export-selected");
  if (exportBtn) {
    exportBtn.onclick = () => {
      if (!findingsState.selectedIds.size) return;
      const type = document.getElementById("export-type")?.value || "json";
      const sid = findingsState.activeSessionId || state.sessions?.[0]?.id;
      if (!sid) return;
      const endpoint = type === "markdown" ? "markdown" : "json";
      const url = `/api/v1/scan/${sid}/report/${endpoint}${state.apiKey ? `?api_key=${encodeURIComponent(state.apiKey)}` : ""}`;
      const a = document.createElement("a");
      a.href = url;
      a.download = `aegis-selected-${sid}.${endpoint === "markdown" ? "md" : "json"}`;
      a.click();
    };
  }
}

