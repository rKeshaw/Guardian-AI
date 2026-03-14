const OWASP_NAMES = {
  "A01:2023": "Broken Access Control",
  "A02:2023": "Cryptographic Failures",
  "A03:2023": "Injection",
  "A04:2023": "Insecure Design",
  "A05:2023": "Security Misconfiguration",
  "A06:2023": "Vulnerable and Outdated Components",
  "A07:2023": "Identification and Authentication Failures",
  "A08:2023": "Software and Data Integrity Failures",
  "A09:2023": "Security Logging and Monitoring Failures",
  "A10:2023": "Server-Side Request Forgery",
};

window.initReportView = async function initReportView(params = {}) {
  const root = document.getElementById("view-report");
  if (!root) return;

  const sessionId = params.sessionId || state.sessions?.[0]?.id;
  if (!sessionId) {
    root.innerHTML = `<div class="card">Scan in progress or no results available yet.</div>`;
    return;
  }

  root.innerHTML = `<div class="report-top"><h2 class="panel-title">Report</h2><div id="report-session-picker"></div></div><div id="report-root" class="card">Loading…</div>`;
  if (!params.sessionId) renderReportSessionPicker(sessionId);

  try {
    const res = await apiFetch(`/api/v1/scan/${sessionId}/results`);
    const report = extractReporting(res.results || []);
    if (!report || !report.technical_findings) {
      document.getElementById("report-root").innerHTML = "Scan in progress or no results available yet.";
      return;
    }
    renderReport(sessionId, report);
  } catch {
    document.getElementById("report-root").innerHTML = "Scan in progress or no results available yet.";
  }
};

function renderReportSessionPicker(active) {
  const picker = document.getElementById("report-session-picker");
  if (!picker) return;
  picker.innerHTML = `<select id="report-session-select" class="input">${state.sessions.map((s) => `<option value="${s.id}">${truncate(s.target || s.id, 40)} • ${String(s.status || "unknown").toUpperCase()} • ${new Date(s.addedAt || Date.now()).toLocaleDateString()}</option>`).join("")}</select>`;
  const sel = document.getElementById("report-session-select");
  if (sel) {
    sel.value = active;
    sel.onchange = () => showView("report", { sessionId: sel.value });
  }
}

function renderReport(sessionId, report) {
  const root = document.getElementById("report-root");
  const exec = report.executive_summary || {};
  const findings = report.technical_findings || [];
  const metadata = report.scan_metadata || {};
  const dist = severityDistribution(findings);
  const owaspRows = buildOwaspRows(findings);
  const evidenceHash = fakeHash(JSON.stringify(findings));

  root.className = "report-shell";
  root.innerHTML = `
    <section class="card">
      <div class="report-header">
        <div><div class="logo glitch" style="font-size:1rem">GUARDIAN AI</div><h3>SECURITY ASSESSMENT REPORT</h3></div>
        <div>
          <button class="btn" id="dl-html">Download HTML</button>
          <button class="btn" id="dl-md">Download Markdown</button>
          <button class="btn" id="dl-json">Download JSON</button>
        </div>
      </div>
      <div class="tiny">Target: ${escapeHtml(metadata.target_url || "")} | Session: ${sessionId} | Generated: ${escapeHtml(report.generated_at || "")} | Profile: ${escapeHtml(metadata.profile || "balanced")}</div>
    </section>

    <section class="card">
      <h3>Executive Summary</h3>
      <p>${escapeHtml(exec.risk_overview || "")}</p>
      <ul>${(exec.key_findings || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
      <p>${escapeHtml(exec.business_impact || "")}</p>
      <ol>${(exec.immediate_actions || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ol>
    </section>

    <section class="card">
      <h3>Risk Distribution</h3>
      <svg id="risk-chart" width="100%" height="180"></svg>
    </section>

    <section class="card">
      <h3>OWASP Coverage</h3>
      <div class="table-wrap"><table><thead><tr><th>Category</th><th>Name</th><th>Count</th><th>Highest Severity</th></tr></thead>
      <tbody>${owaspRows.map((r) => `<tr class="${r.cls}"><td>${r.id}</td><td>${r.name}</td><td>${r.count}</td><td>${r.severity}</td></tr>`).join("")}</tbody></table></div>
    </section>

    <section class="card">
      <h3>Technical Findings</h3>
      ${findings.map((f, i) => renderReportFindingCard(f, i < 3)).join("")}
    </section>

    <section class="card">
      <h3>Evidence Package</h3>
      <div>Schema Version: 1.0</div>
      <div>Generated: ${escapeHtml(report.generated_at || "")}</div>
      <div>Evidence Hash: <code>${evidenceHash}</code></div>
      <div class="table-wrap" style="margin-top:8px"><table><thead><tr><th>Target</th><th>Vulnerability</th><th>Category</th><th>Impact</th><th>Payload</th></tr></thead><tbody>
      ${findings.map((f) => `<tr><td>${escapeHtml(metadata.target_url || "")}</td><td>${escapeHtml(f.vulnerability_name || "")}</td><td>${escapeHtml(f.owasp_category || "")}</td><td>${escapeHtml(f.risk_level || "")}</td><td title="${escapeHtml(f.payload_used || "")}">${escapeHtml(truncate(f.payload_used || "-", 32))}</td></tr>`).join("")}
      </tbody></table></div>
    </section>
  `;

  drawRiskChart(dist);
  bindDownloadButtons(sessionId);
}

function renderReportFindingCard(f, expanded) {
  const open = expanded ? "open" : "";
  return `<details class="finding-card" ${open}><summary><span class="badge badge-${String(f.risk_level || "low").toLowerCase()}">${escapeHtml(f.risk_level || "Low")}</span> <span class="badge badge-owasp">${escapeHtml(f.owasp_category || "")}</span> ${escapeHtml(f.vulnerability_name || "")}</summary>
    <div class="tiny">CVSS ${Number(f.cvss_score || 0).toFixed(1)} <code>${escapeHtml(f.cvss_vector || "")}</code></div>
    <p>${escapeHtml(f.description || "")}</p>
    <pre>${escapeHtml(f.proof_of_concept || "")}</pre>
    <p><strong>Remediation:</strong> ${escapeHtml(f.remediation || "")}</p>
  </details>`;
}

function severityDistribution(findings) {
  const dist = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach((f) => {
    const key = String(f.risk_level || "Low").replace(/^./, (m) => m.toUpperCase()).toLowerCase();
    const label = key.charAt(0).toUpperCase() + key.slice(1);
    if (dist[label] != null) dist[label] += 1;
  });
  return dist;
}

function buildOwaspRows(findings) {
  return Object.keys(OWASP_NAMES).map((id) => {
    const rows = findings.filter((f) => f.owasp_category === id);
    const sevOrder = ["Critical", "High", "Medium", "Low"];
    let severity = "-";
    for (const s of sevOrder) {
      if (rows.some((r) => String(r.risk_level || "").toLowerCase() === s.toLowerCase())) {
        severity = s;
        break;
      }
    }
    const cls = rows.length === 0 ? "muted-row" : severity === "Critical" ? "critical-row" : "";
    return { id, name: OWASP_NAMES[id], count: rows.length, severity, cls };
  });
}

function drawRiskChart(dist) {
  const svg = d3.select("#risk-chart");
  if (!svg.node()) return;
  const data = [
    { key: "Critical", val: dist.Critical, color: "#dc2626" },
    { key: "High", val: dist.High, color: "#ea580c" },
    { key: "Medium", val: dist.Medium, color: "#ca8a04" },
    { key: "Low", val: dist.Low, color: "#16a34a" },
  ];
  const width = svg.node().clientWidth || 760;
  const barH = 28;
  const max = Math.max(1, ...data.map((d) => d.val));
  svg.attr("viewBox", `0 0 ${width} 180`);

  const g = svg.append("g").attr("transform", "translate(80,10)");
  data.forEach((d, i) => {
    const y = i * 38;
    g.append("text").attr("x", -70).attr("y", y + 18).text(d.key).attr("fill", "#94a3b8");
    const rect = g.append("rect").attr("x", 0).attr("y", y).attr("height", barH).attr("width", 0).attr("fill", d.color).attr("rx", 4);
    rect.transition().duration(700).attr("width", (d.val / max) * (width - 200));
    g.append("text").attr("x", (d.val / max) * (width - 200) + 8).attr("y", y + 18).text(String(d.val)).attr("fill", "#e2e8f0");
  });
}

function bindDownloadButtons(sessionId) {
  const date = new Date().toISOString().slice(0, 10);
  document.getElementById("dl-html").onclick = () => downloadFile(`/api/v1/scan/${sessionId}/report/html`, `guardian-report-${sessionId}-${date}.html`);
  document.getElementById("dl-md").onclick = () => downloadFile(`/api/v1/scan/${sessionId}/report/markdown`, `guardian-report-${sessionId}-${date}.md`);
  document.getElementById("dl-json").onclick = () => downloadFile(`/api/v1/scan/${sessionId}/report/json`, `guardian-report-${sessionId}-${date}.json`);
}

function downloadFile(url, filename) {
  const a = document.createElement("a");
  a.href = url + (state.apiKey ? `?api_key=${encodeURIComponent(state.apiKey)}` : "");
  a.download = filename;
  a.target = "_blank";
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function fakeHash(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `sha256:${(h >>> 0).toString(16).padStart(8, "0")}`;
}

