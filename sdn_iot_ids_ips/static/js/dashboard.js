/* ================================================================
   SDN IoT AI-IDS/IPS — Live Dashboard JS
   ================================================================ */

const ATTACK_LABELS = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"};
const socket = io();

// ── Connection status ────────────────────────────────────────────
const connEl = document.getElementById("conn-status");
socket.on("connect", () => {
  connEl.textContent = "Connected";
  connEl.className = "badge badge-green";
});
socket.on("disconnect", () => {
  connEl.textContent = "Disconnected";
  connEl.className = "badge badge-red";
});

// ── Live stats update ────────────────────────────────────────────
socket.on("stats_update", (data) => {
  // Metric scorecards
  const m = data.metrics || {};
  setText("val-accuracy",    fmt(m.accuracy));
  setText("val-f1",          fmt(m.f1_macro));
  setText("val-recall",      fmt(m.recall_macro));
  setText("val-mse",         m.mse != null ? m.mse.toExponential(3) : "—");

  const ips = data.ips_stats || {};
  setText("val-total",       ips.total_events    || 0);
  setText("val-attacks",     ips.attack_events   || 0);
  setText("val-mitigations", (data.active_mitigations || []).length);
  setText("val-snort",       (data.snort_stats   || {}).total || 0);
  setText("val-suricata",    (data.suricata_stats || {}).total || 0);

  // IPS action table
  renderKV("tbl-actions", ips.by_action || {});

  // Class distribution table
  const classRows = {};
  Object.entries(ips.by_class || {}).forEach(([k, v]) => {
    classRows[ATTACK_LABELS[k] || k] = v;
  });
  renderKV("tbl-classes", classRows);

  // Active mitigations table
  renderMitigations(data.active_mitigations || []);
});

// ── Helpers ─────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function fmt(v) {
  return v != null ? (v * 100).toFixed(2) + "%" : "—";
}

function renderKV(tableId, obj) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody) return;
  tbody.innerHTML = Object.entries(obj).map(([k, v]) =>
    `<tr><td>${k}</td><td>${v}</td></tr>`
  ).join("") || `<tr><td colspan="2" style="color:#6a7090">No data</td></tr>`;
}

function renderMitigations(list) {
  const tbody = document.querySelector("#tbl-mitigations tbody");
  if (!tbody) return;
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:#6a7090">None active</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(m => {
    const exp = m.expires_at
      ? new Date(m.expires_at * 1000).toLocaleTimeString()
      : "∞";
    return `<tr><td>${m.src_ip}</td><td>${m.action}</td><td>${exp}</td></tr>`;
  }).join("");
}

// ── Single flow prediction ───────────────────────────────────────
document.getElementById("btn-predict")?.addEventListener("click", async () => {
  const raw = document.getElementById("feat-input").value.trim();
  const srcIp = document.getElementById("src-ip-input").value.trim() || "0.0.0.0";
  const enforce = document.getElementById("enforce-chk").checked;

  if (!raw) { alert("Enter a feature vector"); return; }

  let features;
  try {
    features = raw.split(/[,\s]+/).map(Number);
    // Pad to 78 if shorter
    while (features.length < 78) features.push(0);
    features = features.slice(0, 78);
  } catch {
    alert("Invalid feature vector"); return;
  }

  const res = await fetch("/api/v1/predict", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({features, src_ip: srcIp, enforce}),
  });
  const json = await res.json();
  document.getElementById("predict-result").textContent = JSON.stringify(json, null, 2);
});

// ── Training ─────────────────────────────────────────────────────
document.getElementById("btn-train")?.addEventListener("click", async () => {
  document.getElementById("train-result").textContent = "Training started…";
  const res = await fetch("/api/v1/train", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({epochs: 10, n_samples: 5000}),
  });
  const json = await res.json();
  document.getElementById("train-result").textContent = JSON.stringify(json, null, 2);
});
