/**
 * Scantrap IDS — Dashboard v2
 * Professional live dashboard JS
 */

"use strict";

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function fmt(n) {
    n = Number(n) || 0;
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
    if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
    return String(n);
}

function pct(num, total) {
    if (!total) return "0%";
    return `${Math.round((num / total) * 100)}%`;
}

function badgeFor(type) {
    const t = (type || "").toLowerCase();
    if (t.includes("port") || t.includes("scan"))
        return `<span class="badge badge--scan">Port Scan</span>`;
    if (t.includes("arp"))
        return `<span class="badge badge--arp">ARP Spoofing</span>`;
    if (t.includes("spike") || t.includes("traffic"))
        return `<span class="badge badge--spike">Traffic Spike</span>`;
    return `<span class="badge badge--other">${type}</span>`;
}

function flashKPI(el) {
    if (!el) return;
    el.classList.remove("flash");
    void el.offsetWidth; // reflow
    el.classList.add("flash");
    el.addEventListener("animationend", () => el.classList.remove("flash"), { once: true });
}


// ─────────────────────────────────────────────────────────────
// Canvas PPS Chart
// ─────────────────────────────────────────────────────────────
const HIST_LEN = 60;
const history = new Array(HIST_LEN).fill(0);
const canvas = $("ppsChart");
const ctx = canvas.getContext("2d");

function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

function drawChart() {
    const W = canvas.getBoundingClientRect().width;
    const H = canvas.getBoundingClientRect().height;
    const PAD = { t: 14, b: 8, l: 0, r: 0 };
    const innerH = H - PAD.t - PAD.b;
    const innerW = W - PAD.l - PAD.r;
    const step = innerW / (HIST_LEN - 1);
    const maxVal = Math.max(...history, 10);

    ctx.clearRect(0, 0, W, H);

    // ── Grid ──
    ctx.strokeStyle = "rgba(255,255,255,.04)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
        const y = PAD.t + (innerH / 3) * i;
        ctx.beginPath();
        ctx.moveTo(PAD.l, y);
        ctx.lineTo(W - PAD.r, y);
        ctx.stroke();
    }

    // ── Y-axis labels ──
    ctx.fillStyle = "rgba(100,116,139,.5)";
    ctx.font = `10px JetBrains Mono, monospace`;
    ctx.textAlign = "left";
    ctx.fillText(`${maxVal}`, 4, PAD.t - 2);
    ctx.fillText("0", 4, H - PAD.b + 2);

    // Helper: data point → canvas coords
    const cx = i => PAD.l + i * step;
    const cy = v => PAD.t + innerH * (1 - v / maxVal);

    // ── Gradient fill ──
    const grad = ctx.createLinearGradient(0, PAD.t, 0, H);
    grad.addColorStop(0, "rgba(34,211,238,.22)");
    grad.addColorStop(.5, "rgba(56,189,248,.08)");
    grad.addColorStop(1, "rgba(56,189,248,0)");

    ctx.beginPath();
    history.forEach((v, i) => {
        const x = cx(i), y = cy(v);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(cx(HIST_LEN - 1), H);
    ctx.lineTo(cx(0), H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // ── Stroke ──
    ctx.beginPath();
    history.forEach((v, i) => {
        const x = cx(i), y = cy(v);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "rgba(34,211,238,.8)";
    ctx.lineWidth = 1.5;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    // ── Dot at latest value ──
    const lx = cx(HIST_LEN - 1);
    const ly = cy(history[HIST_LEN - 1]);
    ctx.beginPath();
    ctx.arc(lx, ly, 3, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(34,211,238,1)";
    ctx.fill();
}

window.addEventListener("resize", () => { resizeCanvas(); drawChart(); });
resizeCanvas();
drawChart();


// ─────────────────────────────────────────────────────────────
// Alert Table
// ─────────────────────────────────────────────────────────────
let alertCount = 0;
let lastAlertId = 0;

function clearEmptyState() {
    const tbody = $("alertBody");
    const empty = tbody.querySelector("tr:has(.empty-state)");
    if (empty) empty.remove();
}

function prependRow(alert) {
    clearEmptyState();

    alertCount++;
    const tr = document.createElement("tr");
    tr.className = "row-new";
    // Truncate long details
    const details = (alert.details || "—").slice(0, 80);
    tr.innerHTML = `
    <td class="col-id">${alertCount}</td>
    <td class="col-time">${alert.timestamp}</td>
    <td class="col-ip">${alert.src_ip}</td>
    <td class="col-type">${badgeFor(alert.attack_type)}</td>
    <td class="col-details">${details}</td>
  `;
    $("alertBody").prepend(tr);

    // Cap at 300 rows
    const tbody = $("alertBody");
    while (tbody.rows.length > 300) tbody.deleteRow(tbody.rows.length - 1);

    $("alertCountLabel").textContent = `${alertCount} event${alertCount !== 1 ? "s" : ""}`;
}

function loadInitialAlerts() {
    fetch("/api/alerts?limit=50")
        .then(r => r.json())
        .then(alerts => {
            [...alerts].reverse().forEach(a => {
                prependRow(a);
                lastAlertId = Math.max(lastAlertId, a.id || 0);
            });
        })
        .catch(console.error);
}

// Poll for new rows every 3s
setInterval(() => {
    fetch("/api/alerts?limit=20")
        .then(r => r.json())
        .then(rows => {
            rows.forEach(a => {
                if ((a.id || 0) > lastAlertId) {
                    prependRow(a);
                    lastAlertId = Math.max(lastAlertId, a.id);
                }
            });
        })
        .catch(() => { });
}, 3000);

$("clearBtn").addEventListener("click", () => {
    $("alertBody").innerHTML = `
    <tr><td colspan="5">
      <div class="empty-state">
        <div class="empty-icon">🔎</div>
        <div class="empty-text">Cleared — new events will appear here</div>
      </div>
    </td></tr>`;
    alertCount = 0;
    $("alertCountLabel").textContent = "0 events";
});


// ─────────────────────────────────────────────────────────────
// Stats Update
// ─────────────────────────────────────────────────────────────
let prev = { port_scans: 0, arp_spoofs: 0, traffic_spikes: 0 };

function updateStats(stats, counts) {
    const pps = Number(stats.pps || 0);
    const packets = Number(stats.total_packets || 0);
    const portScans = Number(stats.port_scans || 0);
    const arpSpoofs = Number(stats.arp_spoofs || 0);
    const spikes = Number(stats.traffic_spikes || 0);

    // KPI values
    $("statPackets").textContent = fmt(packets);
    $("statPPS").textContent = pps.toFixed(1);
    $("statScans").textContent = fmt(portScans);
    $("statARPs").textContent = fmt(arpSpoofs);
    $("statSpikes").textContent = fmt(spikes);

    // Header
    $("headerPPS").textContent = `${pps.toFixed(1)} pps`;
    $("ppsLive").textContent = `${pps.toFixed(1)} pps`;

    // KPI sub-labels
    $("scanTrend").textContent = portScans ? `${portScans} detected` : "none detected";
    $("arpTrend").textContent = arpSpoofs ? `${arpSpoofs} detected` : "none detected";
    $("spikeTrend").textContent = spikes ? `${spikes} detected` : "none detected";

    // Flash on new detections
    if (portScans > prev.port_scans) flashKPI($("kpiScan"));
    if (arpSpoofs > prev.arp_spoofs) flashKPI($("kpiARP"));
    if (spikes > prev.traffic_spikes) flashKPI($("kpiSpike"));
    prev = { port_scans: portScans, arp_spoofs: arpSpoofs, traffic_spikes: spikes };

    // Breakdown
    const scanC = Number(counts["Port Scan"] || 0);
    const arpC = Number(counts["ARP Spoofing"] || 0);
    const spikeC = Number(counts["Traffic Spike"] || 0);
    const total = scanC + arpC + spikeC;

    $("bdTotal").textContent = total;
    $("bdScanCount").textContent = scanC;
    $("bdARPCount").textContent = arpC;
    $("bdSpikeCount").textContent = spikeC;
    $("bdScanPct").textContent = total ? pct(scanC, total) : "";
    $("bdARPPct").textContent = total ? pct(arpC, total) : "";
    $("bdSpikePct").textContent = total ? pct(spikeC, total) : "";

    const maxBar = Math.max(scanC, arpC, spikeC, 1);
    $("barScan").style.width = `${(scanC / maxBar) * 100}%`;
    $("barARP").style.width = `${(arpC / maxBar) * 100}%`;
    $("barSpike").style.width = `${(spikeC / maxBar) * 100}%`;

    // Chart
    history.shift();
    history.push(pps);
    drawChart();

    // Footer
    $("footerStats").textContent = `${fmt(packets)} pkts · ${pps.toFixed(1)} pps · ${total} alerts`;
}


// ─────────────────────────────────────────────────────────────
// WebSocket
// ─────────────────────────────────────────────────────────────
const socket = io({ transports: ["websocket"] });

socket.on("connect", () => {
    const chip = $("statusChip");
    chip.classList.add("live");
    $("statusLabel").textContent = "Live";
});

socket.on("disconnect", () => {
    const chip = $("statusChip");
    chip.classList.remove("live");
    $("statusLabel").textContent = "Reconnecting";
});

socket.on("update", data => {
    updateStats(data.stats || {}, data.counts || {});
});


// ─────────────────────────────────────────────────────────────
// Clock
// ─────────────────────────────────────────────────────────────
function tick() {
    const now = new Date();
    $("headerClock").textContent = now.toLocaleTimeString("en-US", {
        hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
    });
}
tick();
setInterval(tick, 1000);


// ─────────────────────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────────────────────
loadInitialAlerts();
