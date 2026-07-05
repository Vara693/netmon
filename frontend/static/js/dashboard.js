/**
 * dashboard.js — NetMon Real-Time Dashboard Controller
 *
 * Polls the Flask API every 5 seconds and updates all UI components:
 *   • Stat cards (PPS, bandwidth, totals, connections, alert count)
 *   • Traffic-over-time line chart
 *   • Protocol distribution doughnut chart
 *   • Top talkers table
 *   • Live alerts feed
 */

"use strict";

// ─── Constants ────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS  = 5000;   // stats refresh rate
const ALERT_POLL_MS     = 8000;   // alerts refresh rate (slightly offset)
const TRAFFIC_MAX_POINTS = 30;    // points shown on the line chart

// Chart.js color palette (RGBA strings for consistency)
const PROTO_COLORS = [
  "rgba(0,200,255,0.85)",    // cyan
  "rgba(0,255,136,0.85)",    // green
  "rgba(255,170,0,0.85)",    // amber
  "rgba(153,102,255,0.85)",  // purple
  "rgba(255,51,85,0.85)",    // red
  "rgba(0,136,255,0.85)",    // blue
  "rgba(255,200,0,0.85)",    // yellow
  "rgba(100,200,100,0.85)",  // light green
];

// ─── State ────────────────────────────────────────────────────────────────────
let trafficChart   = null;
let protocolChart  = null;
let isConnected    = false;
let alertCount     = 0;

const trafficLabels = [];
const ppsData       = [];
const bwData        = [];

// ─── Initialise on DOM Ready ──────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  fetchStats();
  fetchAlerts();

  setInterval(fetchStats,  POLL_INTERVAL_MS);
  setInterval(fetchAlerts, ALERT_POLL_MS);
});

// ═════════════════════════════════════════════════════════════════════════════
// CHART INITIALISATION
// ═════════════════════════════════════════════════════════════════════════════

function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
  };

  // ── Traffic Line Chart ────────────────────────────────────────────────────
  const trafficCtx = document.getElementById("trafficChart").getContext("2d");
  trafficChart = new Chart(trafficCtx, {
    type: "line",
    data: {
      labels: trafficLabels,
      datasets: [
        {
          label: "Packets/sec",
          data: ppsData,
          borderColor: "rgba(0,200,255,0.9)",
          backgroundColor: "rgba(0,200,255,0.05)",
          borderWidth: 1.5,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
          yAxisID: "yPps",
        },
        {
          label: "Bandwidth (Mbps)",
          data: bwData,
          borderColor: "rgba(0,255,136,0.8)",
          backgroundColor: "rgba(0,255,136,0.05)",
          borderWidth: 1.5,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
          yAxisID: "yBw",
        },
      ],
    },
    options: {
      ...chartDefaults,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: {
            color: "rgba(200,224,255,0.6)",
            font: { family: "'Courier New', monospace", size: 10 },
            boxWidth: 12,
          },
        },
        tooltip: {
          backgroundColor: "rgba(6,12,26,0.95)",
          borderColor: "rgba(0,200,255,0.3)",
          borderWidth: 1,
          titleColor: "#00c8ff",
          bodyColor: "#c8e0ff",
          bodyFont: { family: "'Courier New', monospace", size: 11 },
        },
      },
      scales: {
        x: {
          ticks: { color: "rgba(74,112,144,0.8)", font: { size: 9 }, maxRotation: 0, maxTicksLimit: 8 },
          grid:  { color: "rgba(0,200,255,0.05)" },
        },
        yPps: {
          position: "left",
          ticks: { color: "rgba(0,200,255,0.7)", font: { size: 10 } },
          grid:  { color: "rgba(0,200,255,0.05)" },
          title: { display: true, text: "Pkts/s", color: "rgba(0,200,255,0.5)", font: { size: 9 } },
        },
        yBw: {
          position: "right",
          ticks: { color: "rgba(0,255,136,0.7)", font: { size: 10 } },
          grid:  { drawOnChartArea: false },
          title: { display: true, text: "Mbps", color: "rgba(0,255,136,0.5)", font: { size: 9 } },
        },
      },
    },
  });

  // ── Protocol Doughnut Chart ───────────────────────────────────────────────
  const protoCtx = document.getElementById("protocolChart").getContext("2d");
  protocolChart = new Chart(protoCtx, {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: PROTO_COLORS,
        borderColor: "rgba(4,8,15,1)",
        borderWidth: 2,
        hoverOffset: 4,
      }],
    },
    options: {
      ...chartDefaults,
      cutout: "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "rgba(200,224,255,0.6)",
            font: { family: "'Courier New', monospace", size: 9 },
            boxWidth: 10,
            padding: 8,
          },
        },
        tooltip: {
          backgroundColor: "rgba(6,12,26,0.95)",
          borderColor: "rgba(0,200,255,0.3)",
          borderWidth: 1,
          titleColor: "#00c8ff",
          bodyColor: "#c8e0ff",
          bodyFont: { family: "'Courier New', monospace", size: 11 },
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed.toFixed(1)}%`,
          },
        },
      },
    },
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// DATA FETCHING
// ═════════════════════════════════════════════════════════════════════════════

async function fetchStats() {
  try {
    const res  = await fetch("/api/stats/realtime");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    setConnected(true);
    updateStatCards(data);
    updateTrafficChart(data);
    updateProtocolChart(data.protocol_dist || {});
    updateTopTalkers(data.top_talkers || []);

    document.getElementById("lastUpdated").textContent = new Date().toLocaleTimeString();
    document.getElementById("dbStatus").textContent    =
      `db: ${data.total_packets > 0 ? "OK" : "no data"}`;

  } catch (err) {
    console.warn("Stats fetch error:", err);
    setConnected(false);
  }
}

async function fetchAlerts() {
  try {
    const res   = await fetch("/api/alerts?limit=50&source=memory");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data  = await res.json();
    const alerts = data.alerts || [];

    updateAlertsFeed(alerts);
    updateAlertCount(alerts.length);

  } catch (err) {
    console.warn("Alerts fetch error:", err);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// UI UPDATERS
// ═════════════════════════════════════════════════════════════════════════════

function updateStatCards(data) {
  const pps = data.packets_per_second ?? 0;
  const bw  = data.bandwidth_mbps     ?? 0;

  setText("val-pps",   pps.toFixed(0));
  setText("val-bw",    bw.toFixed(2));
  setText("val-total", fmtNum(data.total_packets ?? 0));
  setText("val-conns", data.active_connections ?? 0);

  // Highlight spike
  const ppsEl = document.getElementById("val-pps");
  if (pps > 300) {
    ppsEl.classList.add("spike");
  } else {
    ppsEl.classList.remove("spike");
  }
}

function updateAlertCount(count) {
  setText("val-alerts", count);
  const card = document.getElementById("card-alerts");
  card.style.borderColor = count > 0 ? "rgba(255,51,85,0.5)" : "";
}

function updateTrafficChart(data) {
  const now = new Date().toLocaleTimeString("en-GB", { hour12: false });

  // Push new data
  trafficLabels.push(now);
  ppsData.push(parseFloat((data.packets_per_second ?? 0).toFixed(2)));
  bwData.push(parseFloat((data.bandwidth_mbps ?? 0).toFixed(4)));

  // Trim to window
  if (trafficLabels.length > TRAFFIC_MAX_POINTS) {
    trafficLabels.shift();
    ppsData.shift();
    bwData.shift();
  }

  trafficChart.update("none");   // "none" = no animation → smoother updates
}

function updateProtocolChart(protoObj) {
  const labels = Object.keys(protoObj);
  const values = Object.values(protoObj);

  protocolChart.data.labels = labels;
  protocolChart.data.datasets[0].data = values;
  protocolChart.update();
}

function updateTopTalkers(talkers) {
  const tbody = document.getElementById("talkersBody");

  if (!talkers || talkers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-row">No data yet…</td></tr>`;
    return;
  }

  tbody.innerHTML = talkers.map(t => {
    const pct   = Math.min(t.percentage ?? 0, 100);
    const bytes = fmtBytes(t.bytes ?? 0);
    return `
      <tr>
        <td class="ip-cell">${escHtml(t.ip)}</td>
        <td>${fmtNum(t.packets)}</td>
        <td>${bytes}</td>
        <td>
          <div class="usage-bar-wrap">
            <div class="usage-bar">
              <div class="usage-bar-fill" style="width:${pct}%"></div>
            </div>
            <span>${pct.toFixed(1)}%</span>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function updateAlertsFeed(alerts) {
  const feed = document.getElementById("alertsFeed");

  if (!alerts || alerts.length === 0) {
    feed.innerHTML = `<div class="alert-empty">No alerts detected.</div>`;
    return;
  }

  feed.innerHTML = alerts.map(a => {
    const ts = a.timestamp
      ? new Date(a.timestamp).toLocaleTimeString()
      : "—";
    const sev = (a.severity || "LOW").toUpperCase();
    return `
      <div class="alert-item severity-${sev}">
        <div class="alert-type">${sev} — ${escHtml(a.type || "ALERT")}</div>
        <div class="alert-msg">${escHtml(a.message || "")}</div>
        ${a.source_ip ? `<div class="alert-time">SRC: ${escHtml(a.source_ip)} · ${ts}</div>` : `<div class="alert-time">${ts}</div>`}
      </div>`;
  }).join("");
}

function clearAlertDisplay() {
  document.getElementById("alertsFeed").innerHTML =
    `<div class="alert-empty">Display cleared (data preserved in DB).</div>`;
}

// ─── Connection State ─────────────────────────────────────────────────────────
function setConnected(connected) {
  isConnected = connected;
  const dot   = document.getElementById("statusDot");
  const label = document.getElementById("statusLabel");
  if (connected) {
    dot.className  = "status-dot live";
    label.textContent = "LIVE";
  } else {
    dot.className  = "status-dot error";
    label.textContent = "DISCONNECTED";
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// EXPORT ACTIONS
// ═════════════════════════════════════════════════════════════════════════════

function exportCSV() {
  window.open("/api/export/csv", "_blank");
}

function exportJSON() {
  window.open("/api/export/json", "_blank");
}

// ═════════════════════════════════════════════════════════════════════════════
// UTILITY HELPERS
// ═════════════════════════════════════════════════════════════════════════════

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtNum(n) {
  return Number(n).toLocaleString();
}

function fmtBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}
