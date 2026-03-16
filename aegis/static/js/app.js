const state = {
  currentView: "dashboard",
  currentParams: {},
  sessions: JSON.parse(sessionStorage.getItem("aegis_sessions") || "[]"),
  apiKey: sessionStorage.getItem("aegis_api_key") || "",
  activeWebSockets: {},
  sessionPoller: null,
  healthPoller: null,
};
window.state = state;

function cap(name) {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

function openRightPanel(title, contentHtml) {
  const panel = document.getElementById("right-panel");
  const titleEl = document.getElementById("right-panel-title");
  const contentEl = document.getElementById("right-panel-content");
  if (!panel || !titleEl || !contentEl) return;
  panel.classList.add("open");
  panel.classList.remove("collapsed");
  titleEl.textContent = title || "Details";
  contentEl.innerHTML = contentHtml || "";
}

function closeRightPanel() {
  const panel = document.getElementById("right-panel");
  if (!panel) return;
  panel.classList.remove("open");
  panel.classList.add("collapsed");
}

window.openRightPanel = openRightPanel;
window.closeRightPanel = closeRightPanel;
window.setDetail = (text) => openRightPanel("Details", `<pre>${escapeHtml(String(text || ""))}</pre>`);

function showView(name, params = {}) {
  document.querySelectorAll(".view-panel").forEach((el) => {
    el.style.display = "none";
    el.classList.remove("active");
  });

  const target = document.getElementById(`view-${name}`);
  if (target) {
    target.style.display = "block";
    target.classList.add("active");
  }

  state.currentView = name;
  state.currentParams = params;

  document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active"));
  const navItem = document.querySelector(`[data-view="${name}"]`);
  if (navItem) navItem.classList.add("active");

  const fn = window[`init${cap(name)}View`];
  if (typeof fn === "function") fn(params);
}
window.showView = showView;

async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (state.apiKey) headers["X-API-Key"] = state.apiKey;

  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 401) {
    showApiKeyModal();
    throw new Error("401: API key required");
  }
  if (!resp.ok) throw new Error(`${resp.status}: ${await resp.text()}`);

  const ct = resp.headers.get("content-type") || "";
  if (ct.includes("application/json")) return resp.json();
  return resp.text();
}
window.apiFetch = apiFetch;

function showApiKeyModal() {
  const modal = document.getElementById("api-key-modal");
  if (modal) modal.style.display = "block";
}

function hideApiKeyModal() {
  const modal = document.getElementById("api-key-modal");
  if (modal) modal.style.display = "none";
}

function submitApiKey() {
  const input = document.getElementById("api-key-input");
  state.apiKey = (input?.value || "").trim();
  sessionStorage.setItem("aegis_api_key", state.apiKey);
  hideApiKeyModal();
  initApp();
}
window.submitApiKey = submitApiKey;

function addSession(sessionId, targetUrl) {
  const sessions = state.sessions.filter((s) => s.id !== sessionId);
  sessions.unshift({ id: sessionId, target: targetUrl, addedAt: Date.now(), status: "INITIALIZING" });
  state.sessions = sessions.slice(0, 20);
  sessionStorage.setItem("aegis_sessions", JSON.stringify(state.sessions));
}
window.addSession = addSession;

function truncate(s, n = 64) {
  const v = String(s || "");
  return v.length > n ? `${v.slice(0, n)}…` : v;
}
window.truncate = truncate;

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
window.escapeHtml = escapeHtml;

async function checkHealthAndApiKey() {
  try {
    const health = await apiFetch("/api/v1/health");
    renderSystemStatus(health);
  } catch (err) {
    const message = String(err?.message || "");
    if (message.startsWith("401")) showApiKeyModal();
    else renderSystemStatus(null);
  }
}

function renderSystemStatus(health) {
  const dot = document.getElementById("system-dot");
  const txt = document.getElementById("system-status-text");
  const ollama = document.getElementById("system-ollama");
  const scans = document.getElementById("system-active-scans");

  if (!dot || !txt) return;
  if (!health) {
    dot.className = "status-dot status-degraded";
    txt.textContent = "DEGRADED";
    if (ollama) ollama.textContent = "Ollama: disconnected";
    if (scans) scans.textContent = "Active scans: 0";
    return;
  }

  const status = String(health.status || "starting").toLowerCase();
  if (status === "operational") {
    dot.className = "status-dot status-operational";
    txt.textContent = "OPERATIONAL";
  } else if (status === "starting") {
    dot.className = "status-dot status-starting";
    txt.textContent = "STARTING";
  } else {
    dot.className = "status-dot status-degraded";
    txt.textContent = "DEGRADED";
  }

  const ollamaConnected = !!health?.components?.llm || String(health?.components?.ollama || "").includes("connected");
  if (ollama) ollama.textContent = `Ollama: ${ollamaConnected ? "connected" : "disconnected"}`;
  if (scans) scans.textContent = `Active scans: ${Number(health?.components?.active_sessions || 0)}`;
}

function setupNavigation() {
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => showView(item.dataset.view));
  });

  const newScanBtn = document.getElementById("btn-newscan-top");
  if (newScanBtn) newScanBtn.addEventListener("click", () => showView("newscan"));

  const closeBtn = document.getElementById("right-panel-close");
  if (closeBtn) closeBtn.addEventListener("click", closeRightPanel);
}

async function pollSessionStatuses() {
  const updates = await Promise.all(
    (state.sessions || []).map(async (s) => {
      try {
        const status = await apiFetch(`/api/v1/scan/${s.id}/status`);
        return { ...s, status: status.status, started_at: status.started_at, completed_at: status.completed_at, lastData: status };
      } catch {
        return s;
      }
    }),
  );

  state.sessions = updates;
  sessionStorage.setItem("aegis_sessions", JSON.stringify(state.sessions));

  if (state.currentView === "dashboard" && typeof window.initDashboardView === "function") {
    window.initDashboardView();
  }
}

function startSessionPolling() {
  if (state.sessionPoller) clearInterval(state.sessionPoller);
  state.sessionPoller = setInterval(pollSessionStatuses, 5000);
  pollSessionStatuses();
}

function initApp() {
  checkHealthAndApiKey();
  setupNavigation();
  showView("dashboard");
  startSessionPolling();
  if (state.healthPoller) clearInterval(state.healthPoller);
  state.healthPoller = setInterval(checkHealthAndApiKey, 30000);
}
window.initApp = initApp;

