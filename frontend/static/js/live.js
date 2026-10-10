/* live.js — dashboard live updates (Phase 5)
 *
 * Polls /api/devices + /api/summary every 5s and PATCHES the table in place:
 * existing rows are updated cell-by-cell, new devices are appended, and rows
 * for devices that dropped off are removed. The <table>, its scroll container,
 * and the filter controls are never rebuilt, so scroll position and the current
 * filter selection survive every refresh. Polling pauses while the tab is
 * hidden (document.visibilityState). All dynamic text goes in via textContent,
 * so device-supplied values (hostname, vendor) can't inject HTML.
 */
(function () {
  const POLL_MS = 5000;
  let lastScanBaseSeconds = null, lastScanFetchMs = null;
  // NOTE: the dashboard CHARTS live in charts.js (fed by /api/charts/*). This
  // file only handles the stat tiles, the live device table, and the activity feed.

  function statusBadge(status) {
    const cls = { authorized: "success", unauthorized: "warning", blocked: "danger" }[status] || "secondary";
    const span = document.createElement("span");
    span.className = "badge text-bg-" + cls;
    span.textContent = status === "blocked" ? "flagged" : status;   // UI wording
    return span;
  }

  function applyFilter() {
    const q = (document.getElementById("filter-search").value || "").toLowerCase();
    const st = document.getElementById("filter-status").value;
    document.querySelectorAll("#device-tbody tr").forEach(function (tr) {
      const hay = (tr.dataset.mac + " " + tr.dataset.ip + " " + tr.dataset.vendor).toLowerCase();
      const show = (!st || tr.dataset.status === st) && (!q || hay.indexOf(q) !== -1);
      tr.classList.toggle("d-none", !show);
    });
  }

  function upsertRow(tbody, d) {
    let tr = tbody.querySelector('tr[data-device-id="' + d.id + '"]');
    if (!tr) {
      tr = document.createElement("tr");
      tr.dataset.deviceId = d.id;
      tr.innerHTML =
        '<td data-field="status"></td>' +
        '<td data-field="mac" class="font-monospace"><a></a></td>' +
        '<td data-field="ip" class="font-monospace"></td>' +
        '<td data-field="vendor"></td>' +
        '<td data-field="hostname"></td>' +
        '<td data-field="last_seen" class="text-end text-body-secondary"></td>';
      tbody.appendChild(tr);
    }
    tr.dataset.mac = d.mac || "";
    tr.dataset.ip = d.ip || "";
    tr.dataset.vendor = d.vendor || "";
    tr.dataset.status = d.status || "";

    const st = tr.querySelector('[data-field="status"]');
    st.replaceChildren(statusBadge(d.status));
    const a = tr.querySelector('[data-field="mac"] a');
    a.href = "/devices/" + d.id;
    a.textContent = d.label || d.mac;
    tr.querySelector('[data-field="ip"]').textContent = d.ip || "";
    tr.querySelector('[data-field="vendor"]').textContent = d.vendor || "";
    tr.querySelector('[data-field="hostname"]').textContent = d.hostname || "";
    tr.querySelector('[data-field="last_seen"]').textContent =
      (d.last_seen_ago != null) ? d.last_seen_ago + "s ago" : "";
  }

  async function pollDevices() {
    let data;
    try {
      const r = await fetch("/api/devices");
      if (!r.ok) return;
      data = await r.json();
    } catch (e) { return; }

    const tbody = document.getElementById("device-tbody");
    const seen = new Set();
    data.devices.forEach(function (d) { upsertRow(tbody, d); seen.add(String(d.id)); });
    // Remove rows for devices that are no longer online (disappeared).
    tbody.querySelectorAll("tr[data-device-id]").forEach(function (tr) {
      if (!seen.has(tr.dataset.deviceId)) tr.remove();
    });
    document.getElementById("empty-note").classList.toggle("d-none", data.devices.length > 0);

    if (data.last_scan) {
      lastScanBaseSeconds = data.last_scan.seconds_ago;
      lastScanFetchMs = Date.now();
    }
    applyFilter();   // re-apply the (unchanged) filter to any new rows
  }

  async function pollSummary() {
    let s;
    try {
      const r = await fetch("/api/summary");
      if (!r.ok) return;
      s = await r.json();
    } catch (e) { return; }
    const total = (s.counts.total != null) ? s.counts.total : "";
    document.getElementById("tile-online").textContent = s.counts.online;
    document.getElementById("tile-unauth").textContent = s.counts.unauthorized;
    document.getElementById("tile-alerts").textContent = s.open_alerts;
    const tileTotal = document.getElementById("tile-total");
    if (tileTotal) tileTotal.textContent = total;

    renderActivity(s.activity);
  }

  function updateLastScanLabel() {
    if (lastScanBaseSeconds == null) return;
    const secs = lastScanBaseSeconds + Math.floor((Date.now() - lastScanFetchMs) / 1000);
    const hdr = document.getElementById("hdr-lastscan");
    if (hdr) hdr.textContent = secs + "s";             // header "Last scan Ns ago" chip
  }

  function renderActivity(items) {
    const ul = document.getElementById("activity-feed");
    if (!ul) return;
    ul.replaceChildren();
    const cls = { joined: "success", left: "secondary", present: "light" };
    (items || []).forEach(function (a) {
      const li = document.createElement("li");
      li.className = "list-group-item d-flex justify-content-between px-0 small";
      const left = document.createElement("span");
      const badge = document.createElement("span");
      badge.className = "badge text-bg-" + (cls[a.event] || "light") + (a.event === "present" ? " text-dark" : "");
      badge.textContent = a.event;
      left.appendChild(badge);
      const who = document.createElement("span");     // textContent => no HTML injection
      who.className = "ms-2 font-monospace";
      who.textContent = a.who || "";
      left.appendChild(who);
      const when = document.createElement("span");
      when.className = "text-body-secondary";
      when.textContent = (a.ago != null) ? a.ago + "s ago" : "";
      li.appendChild(left);
      li.appendChild(when);
      ul.appendChild(li);
    });
  }

  async function pollNetstats() {
    if (!document.getElementById("net-download")) return;   // not on this page
    let n;
    try {
      const r = await fetch("/api/netstats");
      if (!r.ok) return;
      n = await r.json();
    } catch (e) { return; }
    const set = function (id, val) { const el = document.getElementById(id); if (el) el.textContent = val; };
    set("net-download", n.down_human || "—");
    set("net-upload", n.up_human || "—");
    set("net-ping", (n.ping_ms != null) ? n.ping_ms + " ms" : "—");
    // Show packet loss only when replies are actually going missing.
    var note = n.ping_target ? "→ " + n.ping_target : "";
    if (n.ping_loss) note += "  ·  " + n.ping_loss + "% loss";
    set("net-gw", note);
  }

  function tick() {
    if (document.visibilityState !== "visible") return;  // pause when tab hidden
    pollDevices();
    pollSummary();
    pollNetstats();
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("filter-search").addEventListener("input", applyFilter);
    document.getElementById("filter-status").addEventListener("change", applyFilter);

    tick();                                   // load immediately
    setInterval(tick, POLL_MS);               // then every 5s (skipped when hidden)
    setInterval(updateLastScanLabel, 1000);   // smooth "N seconds ago" counter
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") tick();   // refresh on return
    });
  });
})();
