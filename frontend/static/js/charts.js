/* charts.js — PWNM data visualizations (Chart.js only).
 *
 * One init per chart, registered by canvas id. A chart initializes only if its
 * canvas is present on the page, so this one file serves every page. On the 5s
 * poll each chart is UPDATED via chart.update() — never destroyed/recreated —
 * so nothing flashes. Empty datasets render a centered message, never a bare axis.
 *
 * Colors mirror web/static/css/pwnm.css EXACTLY (severity colors are reserved).
 */
(function () {
  "use strict";
  const POLL_MS = 5000;

  // Reserved severity colors — same hex as :root in pwnm.css.
  const SEV = { low: "#64748b", medium: "#f59e0b", high: "#ea580c", critical: "#dc2626" };
  const ACCENT = "#a78bfa";                 // single-series magnitude / area (violet)
  const ACCENT_FILL = "rgba(167,139,250,.18)";
  const INK = "#93a0b4";                    // axis/tick/legend TEXT (dark theme)
  const GRID = "rgba(255,255,255,.06)";

  // --- recessive defaults; grid/axes quiet, one y-axis, integer ticks -------
  function baseOptions(extra) {
    const o = {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 250 },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: GRID }, border: { display: false }, ticks: { color: INK } },
        y: { grid: { color: GRID }, border: { display: false },
             ticks: { color: INK, precision: 0 }, beginAtZero: true }
      }
    };
    return Object.assign(o, extra || {});
  }

  // --- empty-state helpers --------------------------------------------------
  function box(id) { const c = document.getElementById(id); return c ? c.closest(".chart-box") : null; }
  function showEmpty(id, msg) {
    const b = box(id); if (!b) return;
    const c = document.getElementById(id); if (c) c.style.display = "none";
    let e = b.querySelector(".chart-empty");
    if (!e) { e = document.createElement("div"); e.className = "chart-empty"; b.appendChild(e); }
    e.textContent = msg; e.style.display = "flex";
  }
  function clearEmpty(id) {
    const b = box(id); if (!b) return;
    const c = document.getElementById(id); if (c) c.style.display = "";
    const e = b.querySelector(".chart-empty"); if (e) e.style.display = "none";
  }

  // --- registry + lifecycle -------------------------------------------------
  const registry = {};   // canvasId -> {url, isEmpty, build, update, emptyMsg, chart}

  function register(canvasId, spec) {
    if (!document.getElementById(canvasId)) return;   // chart not on this page
    registry[canvasId] = Object.assign({ chart: null, range: null }, spec);
  }

  // The chart's URL plus the active date filter (?from=&to=). No range => the
  // endpoint's own default window (last 24h / 7d / 30d / all devices).
  function chartUrl(spec) {
    if (!spec.range) return spec.url;
    return spec.url + (spec.url.indexOf("?") === -1 ? "?" : "&") +
      "from=" + spec.range.from + "&to=" + spec.range.to;
  }

  async function load(canvasId) {
    const spec = registry[canvasId]; if (!spec) return;
    let d;
    try { const r = await fetch(chartUrl(spec)); if (!r.ok) return; d = await r.json(); }
    catch (e) { return; }
    if (spec.isEmpty(d)) {
      if (spec.chart) { spec.chart.destroy(); spec.chart = null; }
      showEmpty(canvasId, spec.emptyMsg);
      return;
    }
    clearEmpty(canvasId);
    if (!spec.chart) spec.chart = spec.build(document.getElementById(canvasId), d);
    else { spec.update(spec.chart, d); spec.chart.update("none"); }   // no flash
    if (spec.only !== undefined) applyOnly(spec);      // keep the severity choice
  }

  function sum(a) { return (a || []).reduce(function (x, y) { return x + y; }, 0); }

  // --- quiet-hours background band (custom plugin; no extra library) --------
  const quietBand = {
    id: "quietBand",
    beforeDatasetsDraw: function (chart) {
      const flags = chart.$quiet; if (!flags || !flags.length) return;
      const area = chart.chartArea, x = chart.scales.x, ctx = chart.ctx;
      const half = (area.right - area.left) / flags.length / 2;
      ctx.save();
      ctx.fillStyle = "rgba(100,116,139,.12)";      // muted blue-grey wash
      flags.forEach(function (on, i) {
        if (!on) return;
        const cx = x.getPixelForValue(i);
        ctx.fillRect(cx - half, area.top, half * 2, area.bottom - area.top);
      });
      ctx.restore();
    }
  };

  // =========================================================================
  // Chart 4.2 / 7.1 — occupancy over time (area, single series)
  // =========================================================================
  register("chart-occupancy", {
    url: "/api/charts/occupancy?hours=24", filterDefault: { key: "24h", label: "Last 24 hours" },
    emptyMsg: "No devices seen in this period",
    isEmpty: function (d) { return !d.data || d.data.length === 0 || sum(d.data) === 0; },
    build: function (canvas, d) {
      const ch = new Chart(canvas, {
        type: "line",
        data: { labels: d.labels, datasets: [{
          label: "Devices online", data: d.data, fill: true, tension: 0.3,
          borderColor: ACCENT, backgroundColor: ACCENT_FILL, borderWidth: 2, pointRadius: 0
        }] },
        options: baseOptions(),
        plugins: [quietBand]
      });
      ch.$quiet = d.quiet;
      return ch;
    },
    update: function (ch, d) {
      ch.data.labels = d.labels; ch.data.datasets[0].data = d.data; ch.$quiet = d.quiet;
    }
  });

  // =========================================================================
  // Chart 6.1 / 7.2 — alerts by severity (bar, reserved severity colors)
  // =========================================================================
  function severityBar(canvasId, url) {
    register(canvasId, {
      url: url, filterDefault: { key: "7", label: "Last 7 days" },
      emptyMsg: "No alerts in this period",
      isEmpty: function (d) { return !d.data || sum(d.data) === 0; },
      build: function (canvas, d) {
        return new Chart(canvas, {
          type: "bar",
          data: { labels: d.labels, datasets: [{
            data: d.data, borderRadius: 4,
            backgroundColor: d.labels.map(function (s) { return SEV[s] || ACCENT; })
          }] },
          options: baseOptions()
        });
      },
      update: function (ch, d) {
        ch.data.labels = d.labels; ch.data.datasets[0].data = d.data;
        ch.data.datasets[0].backgroundColor = d.labels.map(function (s) { return SEV[s] || ACCENT; });
      }
    });
  }
  severityBar("chart-alerts-severity", "/api/charts/alerts-by-severity?days=7");        // 6.1
  severityBar("chart-open-severity", "/api/charts/alerts-by-severity?days=7&open=1");   // 7.2

  // =========================================================================
  // Chart 6.2 — alerts over time (one line per severity; legend required)
  // =========================================================================
  register("chart-alerts-over-time", {
    url: "/api/charts/alerts-over-time?days=30", filterDefault: { key: "30", label: "Last 30 days" },
    emptyMsg: "No alerts in this period",
    isEmpty: function (d) { return !d.series || d.series.every(function (s) { return sum(s.data) === 0; }); },
    build: function (canvas, d) {
      return new Chart(canvas, {
        type: "line",
        data: { labels: d.labels, datasets: d.series.map(function (s) {
          return { label: s.severity, data: s.data, borderColor: SEV[s.severity] || ACCENT,
                   backgroundColor: SEV[s.severity] || ACCENT, borderWidth: 2, tension: 0.3,
                   pointRadius: 0, fill: false };
        }) },
        // The built-in legend is off: severityLegend() renders buttons that
        // ISOLATE a severity (show only it) instead of hiding one at a time.
        options: baseOptions({ plugins: { legend: { display: false } } })
      });
    },
    update: function (ch, d) {
      ch.data.labels = d.labels;
      d.series.forEach(function (s, i) { if (ch.data.datasets[i]) ch.data.datasets[i].data = s.data; });
    }
  });

  // =========================================================================
  // Horizontal magnitude bar — reused by 6.3 (rules), 3.1 (status), 3.2 (vendors)
  // =========================================================================
  function horizontalBar(canvasId, url, emptyMsg, colorFn, filterDefault) {
    register(canvasId, {
      url: url, emptyMsg: emptyMsg,
      filterDefault: filterDefault || { key: "30", label: "Last 30 days" },
      isEmpty: function (d) { return !d.data || sum(d.data) === 0; },
      build: function (canvas, d) {
        return new Chart(canvas, {
          type: "bar",
          data: { labels: d.labels, datasets: [{ data: d.data, borderRadius: 4,
            backgroundColor: colorFn ? d.labels.map(colorFn) : ACCENT }] },
          options: {
            responsive: true, maintainAspectRatio: false, indexAxis: "y",
            animation: { duration: 250 }, plugins: { legend: { display: false } },
            scales: {
              x: { beginAtZero: true, grid: { color: GRID }, border: { display: false },
                   ticks: { color: INK, precision: 0 } },
              y: { grid: { display: false }, border: { display: false }, ticks: { color: INK } }
            }
          }
        });
      },
      update: function (ch, d) {
        ch.data.labels = d.labels; ch.data.datasets[0].data = d.data;
        if (colorFn) ch.data.datasets[0].backgroundColor = d.labels.map(colorFn);
      }
    });
  }
  // Chart 6.3 — alerts by rule (single accent; rules aren't severities).
  horizontalBar("chart-alerts-by-rule", "/api/charts/alerts-by-rule?days=30", "No alerts in this period");

  // Chart 3.1 — devices by status (bar, fixed order authorized/unauth/blocked).
  horizontalBar("chart-device-status", "/api/charts/device-status",
    "No devices seen in this period", null, { key: "all", label: "All devices" });

  // Chart 3.2 — top vendors (bar, tail already folded into "Other" server-side).
  horizontalBar("chart-vendor-distribution", "/api/charts/vendor-distribution?limit=8",
    "No devices seen in this period", null, { key: "all", label: "All devices" });

  // =========================================================================
  // Chart 2.1 — devices found per scan (line, single series, no legend)
  // =========================================================================
  register("chart-scan-history", {
    url: "/api/charts/scan-history?hours=24", filterDefault: { key: "24h", label: "Last 24 hours" },
    emptyMsg: "No scans in this period",
    // Never draw a line with a single point — wait for 2+ scans.
    isEmpty: function (d) { return !d.data || d.data.length < 2; },
    build: function (canvas, d) {
      return new Chart(canvas, {
        type: "line",
        data: { labels: d.labels, datasets: [{
          label: "Devices found", data: d.data, borderColor: ACCENT,
          backgroundColor: ACCENT_FILL, borderWidth: 2, tension: 0.3,
          pointRadius: 0, pointHoverRadius: 4, fill: true    // clean trend line, no per-point spikes
        }] },
        options: baseOptions()
      });
    },
    update: function (ch, d) { ch.data.labels = d.labels; ch.data.datasets[0].data = d.data; }
  });

  // =========================================================================
  // Chart 4.1 — device presence timeline (floating horizontal bars)
  // Each bar is an [start, end] pair in minutes-since-midnight, so it floats
  // rather than starting at zero. One row per device; multiple sessions => more
  // bars on the same row. Container height grows to fit the rows.
  // =========================================================================
  (function () {
    const el = document.getElementById("chart-presence");
    if (!el) return;
    const date = el.dataset.date;
    const url = "/api/charts/presence-timeline" + (date ? "?date=" + encodeURIComponent(date) : "");

    function fitHeight(canvas, rows) {
      const b = canvas.closest(".chart-box");
      if (b) b.style.height = Math.max(200, rows * 30 + 40) + "px";
    }
    function hhmm(v) {
      const h = Math.floor(v / 60), m = Math.round(v % 60);
      return (h < 10 ? "0" : "") + h + ":" + (m < 10 ? "0" : "") + m;
    }
    // Tick spacing that suits the visible window (zoomed-in vs. whole day).
    function stepFor(range) { return range <= 180 ? 30 : (range <= 480 ? 60 : 120); }
    function xBounds(d) {
      const lo = (d.x_min != null) ? d.x_min : 0;
      const hi = (d.x_max != null) ? d.x_max : 1440;
      return { lo: lo, hi: hi, step: stepFor(hi - lo) };
    }

    register("chart-presence", {
      url: url, filter: false,
      emptyMsg: "No devices seen on this day",
      isEmpty: function (d) { return !d.bars || d.bars.length === 0; },
      build: function (canvas, d) {
        fitHeight(canvas, d.labels.length);
        const xb = xBounds(d);
        const ch = new Chart(canvas, {
          type: "bar",
          data: { labels: d.labels, datasets: [{
            data: d.bars.map(function (b) { return { x: b.x, y: b.y }; }),
            backgroundColor: ACCENT, borderRadius: 3, barPercentage: 0.7, categoryPercentage: 0.85
          }] },
          options: {
            responsive: true, maintainAspectRatio: false, indexAxis: "y",
            animation: { duration: 250 },
            plugins: {
              legend: { display: false },
              tooltip: { callbacks: { label: function (ctx) {
                const b = ctx.chart.$bars[ctx.dataIndex]; if (!b) return "";
                return [b.y, "in " + b.join + "  →  out " + b.leave,
                        "duration " + b.dur, b.ip ? "IP " + b.ip : ""].filter(Boolean);
              } } }
            },
            scales: {
              x: { type: "linear", min: xb.lo, max: xb.hi, grid: { color: GRID }, border: { display: false },
                   ticks: { color: INK, stepSize: xb.step, callback: hhmm } },
              y: { type: "category", labels: d.labels, grid: { display: false },
                   border: { display: false }, ticks: { color: INK } }
            }
          }
        });
        ch.$bars = d.bars;
        return ch;
      },
      update: function (ch, d) {
        fitHeight(ch.canvas, d.labels.length);
        const xb = xBounds(d);
        ch.data.labels = d.labels;
        ch.options.scales.y.labels = d.labels;
        ch.options.scales.x.min = xb.lo;
        ch.options.scales.x.max = xb.hi;
        ch.options.scales.x.ticks.stepSize = xb.step;
        ch.data.datasets[0].data = d.bars.map(function (b) { return { x: b.x, y: b.y }; });
        ch.$bars = d.bars;
      }
    });
  })();

  // --- date filter bar (one per chart) ---------------------------------------
  function isoDay(d) {
    return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" +
      String(d.getDate()).padStart(2, "0");
  }
  function daysAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return isoDay(d); }

  const PRESETS = [
    { key: "today", label: "Today" },
    { key: "7", label: "Last 7 days" },
    { key: "30", label: "Last 30 days" },
    { key: "90", label: "Last 90 days" },
  ];

  function presetRange(key) {
    if (key === "today") return { from: daysAgo(0), to: daysAgo(0) };
    const n = parseInt(key, 10);
    return isNaN(n) ? null : { from: daysAgo(n - 1), to: daysAgo(0) };
  }

  function el(tag, cls, attrs) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

  function addFilterBar(canvasId) {
    const spec = registry[canvasId];
    const canvas = document.getElementById(canvasId);
    if (!spec || spec.filter === false || !canvas) return;
    const box = canvas.closest(".chart-box");
    if (!box || box.previousElementSibling && box.previousElementSibling.classList.contains("chart-filter")) return;

    const def = spec.filterDefault || { key: "", label: "Default range" };
    const bar = el("div", "chart-filter");
    const select = el("select", "form-select form-select-sm cf-preset", { "aria-label": "Date range" });
    select.appendChild(new Option(def.label, ""));        // "" = the chart's default window
    PRESETS.forEach(function (p) {
      if (p.key !== def.key) select.appendChild(new Option(p.label, p.key));
    });
    select.appendChild(new Option("Custom range…", "custom"));

    const custom = el("div", "cf-custom");
    custom.hidden = true;
    const today = daysAgo(0);
    const from = el("input", "form-control form-control-sm", { type: "date", max: today, "aria-label": "From date" });
    const to = el("input", "form-control form-control-sm", { type: "date", max: today, "aria-label": "To date" });
    const dash = el("span", "cf-dash"); dash.textContent = "to";
    custom.appendChild(from); custom.appendChild(dash); custom.appendChild(to);

    bar.appendChild(select); bar.appendChild(custom);
    box.parentNode.insertBefore(bar, box);

    function apply(range) {
      spec.range = range;
      load(canvasId);                                     // redraw now; polling keeps the range
    }

    select.addEventListener("change", function () {
      if (select.value === "custom") {
        const r = spec.range || { from: daysAgo(6), to: today };
        from.value = r.from; to.value = r.to;
        custom.hidden = false;
        apply({ from: from.value, to: to.value });
        from.focus();
        return;
      }
      custom.hidden = true;
      apply(select.value ? presetRange(select.value) : null);
    });

    function onDates() {
      if (!from.value || !to.value) return;              // wait for both dates
      let a = from.value, b = to.value;
      if (a > b) { const t = a; a = b; b = t; from.value = a; to.value = b; }
      apply({ from: a, to: b });
    }
    from.addEventListener("change", onDates);
    to.addEventListener("change", onDates);
  }

  // --- severity legend for "alerts over time" --------------------------------
  // Clicking a severity SHOWS ONLY that one (the other three hide). "All"
  // brings every severity back. This replaces Chart.js' default legend, which
  // hides one series per click and can end up showing nothing.
  const SEV_ORDER = ["low", "medium", "high", "critical"];

  function applyOnly(spec) {
    const ch = spec.chart;
    if (!ch) return;
    ch.data.datasets.forEach(function (ds, i) {
      ch.setDatasetVisibility(i, !spec.only || ds.label === spec.only);
    });
    ch.update("none");
    const bar = spec.legendEl;
    if (bar) {
      bar.querySelectorAll(".sev-btn").forEach(function (b) {
        const on = (b.dataset.sev || "") === (spec.only || "");
        b.classList.toggle("active", on);
        b.setAttribute("aria-pressed", on ? "true" : "false");
      });
    }
  }

  function addSeverityLegend(canvasId) {
    const spec = registry[canvasId];
    const canvas = document.getElementById(canvasId);
    if (!spec || !canvas) return;
    const box = canvas.closest(".chart-box");
    if (!box || box.parentNode.querySelector(".sev-legend")) return;

    spec.only = null;                                   // null = show all
    const bar = el("div", "sev-legend", { role: "group", "aria-label": "Filter by severity" });

    function button(sev, label) {
      const b = el("button", "sev-btn", { type: "button", "aria-pressed": "false" });
      b.dataset.sev = sev || "";
      if (sev) {
        const dot = el("span", "sev-dot");
        dot.style.background = SEV[sev];
        b.appendChild(dot);
      }
      b.appendChild(document.createTextNode(label));
      b.addEventListener("click", function () {
        // Clicking the active severity again clears back to "All".
        spec.only = (sev && spec.only !== sev) ? sev : null;
        applyOnly(spec);
      });
      return b;
    }

    SEV_ORDER.forEach(function (sev) {
      bar.appendChild(button(sev, sev.charAt(0).toUpperCase() + sev.slice(1)));
    });
    bar.appendChild(button(null, "All"));               // 5th button, same size

    box.parentNode.insertBefore(bar, box);
    spec.legendEl = bar;
    applyOnly(spec);                                    // mark "All" active
  }

  // --- poll loop ------------------------------------------------------------
  function pollAll() {
    if (document.visibilityState !== "visible") return;   // pause when tab hidden
    Object.keys(registry).forEach(load);
  }
  document.addEventListener("DOMContentLoaded", function () {
    Object.keys(registry).forEach(addFilterBar);          // date filter on each chart
    addSeverityLegend("chart-alerts-over-time");          // severity isolate buttons
    Object.keys(registry).forEach(load);                  // initial paint
    setInterval(pollAll, POLL_MS);
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") pollAll();
    });
  });
})();
