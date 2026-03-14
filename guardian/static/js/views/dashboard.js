window.initDashboardView = async function initDashboardView() {
  await refreshDashboard();
};

function statusBadge(status) {
  const s = String(status || "").toLowerCase();
  if (s === "running") return `<span class="badge b-running">RUNNING</span>`;
  if (s === "completed") return `<span class="badge b-completed">COMPLETED</span>`;
  if (s === "error") return `<span class="badge b-error">ERROR</span>`;
  return `<span class="badge b-initializing">INITIALIZING</span>`;
}

function msToDuration(startedAt, completedAt) {
  if (!startedAt) return "-";
  const start = Date.parse(startedAt);
  const end = completedAt ? Date.parse(completedAt) : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) return "-";
  const sec = Math.max(0, Math.floor((end - start) / 1000));
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function riskRank(risk) {
  const v = String(risk || "").toLowerCase();
  if (v.includes("critical")) return 4;
  if (v.includes("high")) return 3;
  if (v.includes("medium")) return 2;
  return 1;
}

async function refreshDashboard() {
  let health = { components: { active_sessions: 0, available_slots: 0 } };
  try { health = await apiFetch("/api/v1/health"); } catch {}

  let totalFindings = 0;
  let topRisk = "Low";

  for (const s of state.sessions) {
    try {
      const st = await apiFetch(`/api/v1/scan/${s.id}/status`);
      s.status = st.status;
      s.lastData = st;
      totalFindings += Number(st?.results?.graph_exploration?.finding_count || 0);
      const risk = st?.results?.vulnerability_analysis?.overall_risk || "Low";
      if (riskRank(risk) > riskRank(topRisk)) topRisk = risk;
    } catch {}
  }

  document.getElementById("stat-active").textContent = String(health?.components?.active_sessions ?? 0);
  document.getElementById("stat-slots").textContent = String(health?.components?.available_slots ?? 0);
  document.getElementById("stat-findings").textContent = String(totalFindings);
  document.getElementById("stat-risk").textContent = String(topRisk).toUpperCase();

  const tbody = document.getElementById("recent-scans-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (!state.sessions.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="tiny">No scans yet. Start a new scan to begin.</td></tr>`;
    return;
  }

  for (const s of state.sessions) {
    const st = s.lastData || {};
    const status = st.status || s.status || "INITIALIZING";
    const findings = st?.results?.graph_exploration?.finding_count || 0;
    const risk = st?.results?.vulnerability_analysis?.overall_risk || "Unknown";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${statusBadge(status)}</td>
      <td title="${s.target || ""}">${truncate(s.target || "-", 60)}</td>
      <td>${st.started_at ? new Date(st.started_at).toLocaleString() : "-"}</td>
      <td>${msToDuration(st.started_at, st.completed_at)}</td>
      <td>${findings}</td>
      <td>${risk}</td>
      <td>
        <button class="btn" data-act="monitor">View Monitor</button>
        <button class="btn" data-act="report" ${String(status).toLowerCase() === "completed" ? "" : "disabled"}>View Report</button>
      </td>`;

    tr.onclick = () => {
      openRightPanel(
        "Scan Summary",
        `<div><b>Session:</b> ${s.id}</div><div><b>Target:</b> ${escapeHtml(s.target || "-")}</div><div><b>Status:</b> ${String(status).toUpperCase()}</div><div><b>Findings:</b> ${findings}</div>`,
      );
      showView("monitor", { sessionId: s.id });
    };

    tr.querySelector('[data-act="monitor"]').onclick = (e) => {
      e.stopPropagation();
      showView("monitor", { sessionId: s.id });
    };
    tr.querySelector('[data-act="report"]').onclick = (e) => {
      e.stopPropagation();
      showView("report", { sessionId: s.id });
    };

    tbody.appendChild(tr);
  }

  sessionStorage.setItem("guardian_sessions", JSON.stringify(state.sessions));
}

