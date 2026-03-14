window.initNewscanView = function initNewscanView() {
  buildProfileCards();
  buildOwaspChecklist();
  bindNewScanHandlers();
  updatePreviewWarnings();
};

const profiles = {
  safe: { label: "SAFE", phases: ["Recon", "Vuln Analysis", "Hypothesis"], eta: "~5 min" },
  balanced: { label: "BALANCED", phases: ["Recon", "Vuln Analysis", "Hypothesis", "Payload Generation"], eta: "~8 min" },
  aggressive: { label: "AGGRESSIVE", phases: ["All phases enabled"], eta: "~12 min" },
};
let selectedProfile = "aggressive";

function buildProfileCards() {
  const root = document.getElementById("profile-cards");
  if (!root) return;
  root.innerHTML = "";
  Object.entries(profiles).forEach(([key, p]) => {
    const div = document.createElement("div");
    div.className = `profile-card ${key === selectedProfile ? "active" : ""}`;
    div.innerHTML = `<strong>${p.label}</strong><div class="tiny">${p.phases.map((x) => `✓ ${x}`).join("<br>")}</div>`;
    div.addEventListener("click", () => {
      selectedProfile = key;
      buildProfileCards();
      document.getElementById("duration-estimate").textContent = profiles[key].eta;
      updatePreviewWarnings();
    });
    root.appendChild(div);
  });
}

function buildOwaspChecklist() {
  const list = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];
  const root = document.getElementById("owasp-checklist");
  root.innerHTML = list.map((x) => `<div class="tiny">☑ ${x}:2023</div>`).join("");
}

function bindNewScanHandlers() {
  const target = document.getElementById("target-url");
  const depth = document.getElementById("crawl-depth");
  const depthLabel = document.getElementById("crawl-depth-label");
  const authType = document.getElementById("auth-type");
  const sslVerify = document.getElementById("ssl-verify");
  const btn = document.getElementById("initiate-scan-btn");

  if (!target.dataset.bound) {
    target.addEventListener("input", () => {
      validateTarget();
      updatePreviewWarnings();
    });
    target.dataset.bound = "1";
  }
  if (!depth.dataset.bound) {
    depth.addEventListener("input", () => {
      depthLabel.textContent = depth.value;
    });
    depth.dataset.bound = "1";
  }
  if (!authType.dataset.bound) {
    authType.addEventListener("change", renderAuthFields);
    authType.dataset.bound = "1";
  }
  if (!sslVerify.dataset.bound) {
    sslVerify.addEventListener("change", () => {
      document.getElementById("ssl-warning").style.display = sslVerify.checked ? "none" : "block";
      updatePreviewWarnings();
    });
    sslVerify.dataset.bound = "1";
  }
  if (!btn.dataset.bound) {
    btn.addEventListener("click", submitNewScan);
    btn.dataset.bound = "1";
  }

  renderAuthFields();
  validateTarget();
}

function validateTarget() {
  const val = (document.getElementById("target-url").value || "").trim();
  const out = document.getElementById("target-validation");
  if (!val) {
    out.className = "tiny";
    out.textContent = "Enter a target URL.";
    return false;
  }
  const ok = /^https?:\/\/.+/i.test(val);
  out.className = `tiny ${ok ? "ok" : "err"}`;
  out.textContent = ok ? "✓ Valid target URL" : "✗ URL must include http:// or https://";
  return ok;
}

function renderAuthFields() {
  const type = document.getElementById("auth-type").value;
  const root = document.getElementById("auth-fields");
  if (type === "bearer") {
    root.innerHTML = `<textarea id="auth-bearer" class="textarea" placeholder="Bearer token"></textarea>`;
  } else if (type === "basic") {
    root.innerHTML = `<div class="row"><input id="auth-user" class="input" placeholder="username"/><input id="auth-pass" class="input" type="password" placeholder="password"/></div>`;
  } else if (type === "form") {
    root.innerHTML = `<input id="auth-login-url" class="input" placeholder="https://target/login" style="margin-bottom:8px"/>
      <div id="form-kv"></div><button id="add-kv" class="btn" type="button">Add credential pair</button><div class="tiny">Success indicator:</div><input id="auth-success" class="input" placeholder="dashboard or logout"/>`;
    const box = root.querySelector("#form-kv");
    const add = () => {
      const row = document.createElement("div");
      row.className = "row";
      row.innerHTML = `<input class="input kv-k" placeholder="field key"/><input class="input kv-v" placeholder="field value"/>`;
      box.appendChild(row);
    };
    root.querySelector("#add-kv").addEventListener("click", add);
    add();
  } else {
    root.innerHTML = `<div class="tiny">No authentication configured.</div>`;
  }
}

function updatePreviewWarnings() {
  const warnings = [];
  if (!validateTarget()) warnings.push("Target URL is invalid.");
  if (!document.getElementById("ssl-verify").checked) warnings.push("SSL verification disabled.");
  document.getElementById("newscan-warnings").innerHTML = warnings.length ? warnings.map((w) => `⚠ ${w}`).join("<br>") : "No warnings.";
}

function buildConfig() {
  const cfg = {
    crawl_depth: Number(document.getElementById("crawl-depth").value || 2),
    profile: selectedProfile,
    verify_ssl: document.getElementById("ssl-verify").checked,
  };
  const deny = (document.getElementById("deny-cidrs").value || "").trim();
  if (deny) cfg.scan_target_deny_cidrs = deny;

  const type = document.getElementById("auth-type").value;
  if (type !== "none") {
    cfg.auth = { type };
    if (type === "bearer") cfg.auth.bearer_token = document.getElementById("auth-bearer").value || "";
    if (type === "basic") {
      cfg.auth.username = document.getElementById("auth-user").value || "";
      cfg.auth.password = document.getElementById("auth-pass").value || "";
    }
    if (type === "form") {
      cfg.auth.login_url = document.getElementById("auth-login-url").value || "";
      cfg.auth.success_indicator = document.getElementById("auth-success").value || "";
      const creds = {};
      document.querySelectorAll("#form-kv .row").forEach((r) => {
        const k = r.querySelector(".kv-k").value;
        const v = r.querySelector(".kv-v").value;
        if (k) creds[k] = v;
      });
      cfg.auth.credentials = creds;
    }
  }
  return cfg;
}

async function submitNewScan() {
  const errorEl = document.getElementById("newscan-error");
  errorEl.style.display = "none";
  if (!validateTarget()) {
    errorEl.textContent = "Please provide a valid target URL.";
    errorEl.style.display = "block";
    return;
  }

  const btn = document.getElementById("initiate-scan-btn");
  const targetUrl = document.getElementById("target-url").value.trim();
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "INITIATING...";

  try {
    const payload = { target_urls: [targetUrl], config: buildConfig() };
    const resp = await apiFetch("/api/v1/scan/start", { method: "POST", body: JSON.stringify(payload) });
    addSession(resp.session_id, targetUrl);
    setDetail(`Scan ${resp.session_id} started for ${targetUrl}`);
    showView("monitor", { sessionId: resp.session_id });
  } catch (e) {
    errorEl.textContent = `Failed to start scan: ${e.message}`;
    errorEl.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

