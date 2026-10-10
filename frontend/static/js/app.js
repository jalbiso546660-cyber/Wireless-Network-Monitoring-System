/* app.js — small global UI behaviours loaded on every page.
 *
 * Wired here (not via inline onsubmit/onclick) so the Content-Security-Policy
 * can keep forbidding inline scripts and handlers.
 */
(function () {
  "use strict";

  // --- Confirmation guard: <form data-confirm="message"> asks before submit ---
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form && form.matches && form.matches("form[data-confirm]")) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    }
  }, true);

  // --- Auto-submit: <input data-autosubmit> submits its form when changed ------
  // (replaces inline onchange="this.form.submit()", which the CSP blocks)
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (t && t.matches && t.matches("[data-autosubmit]") && t.form) t.form.submit();
  });

  // --- Duration hint: <input data-duration="seconds|minutes|days"> shows its
  //     value in everyday terms under the box ("= 1 hour 30 minutes").
  function humanDuration(value, unit) {
    var n = Number(value);
    if (!isFinite(n) || n <= 0) return "";
    var secs = n * ({ seconds: 1, minutes: 60, days: 86400 }[unit] || 1);
    var parts = [], units = [["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    units.forEach(function (u) {
      var q = Math.floor(secs / u[1]);
      if (q > 0 && parts.length < 2) { parts.push(q + " " + u[0] + (q === 1 ? "" : "s")); secs -= q * u[1]; }
    });
    return parts.length ? "= " + parts.join(" ") : "";
  }
  function updateHint(input) {
    var hint = input.closest(".setting-input");
    hint = hint && hint.querySelector(".dur-hint");
    if (!hint) return;
    var text = humanDuration(input.value, input.dataset.duration);
    // Only worth showing when it adds information (e.g. 90 seconds, not 45 seconds).
    hint.textContent = (text && text !== "= " + input.value + " " + input.dataset.duration &&
                        text !== "= 1 " + input.dataset.duration.replace(/s$/, "")) ? text : "";
  }
  document.addEventListener("input", function (e) {
    if (e.target.matches && e.target.matches("input[data-duration]")) updateHint(e.target);
  });
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("input[data-duration]").forEach(updateHint);
  });

  // --- Mobile sidebar: slide-in menu behind the hamburger --------------------
  function setSidebar(open) {
    var side = document.getElementById("app-sidebar");
    var back = document.querySelector(".sidebar-backdrop");
    var burger = document.querySelector("[data-sidebar-toggle]");
    if (!side) return;
    side.classList.toggle("open", open);
    if (back) back.hidden = !open;
    if (burger) burger.setAttribute("aria-expanded", open ? "true" : "false");
    document.body.classList.toggle("sidebar-open", open);   // locks page scroll
  }
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-sidebar-toggle]")) {
      var side = document.getElementById("app-sidebar");
      setSidebar(!(side && side.classList.contains("open")));
      return;
    }
    if (e.target.closest("[data-sidebar-close]")) { setSidebar(false); return; }
    // Tapping a nav link closes the menu so the page is visible immediately.
    if (e.target.closest("#app-sidebar a")) setSidebar(false);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setSidebar(false);
  });
  window.addEventListener("resize", function () {
    if (window.innerWidth >= 992) setSidebar(false);        // back to desktop
  });

  // --- "Scan now": run it live instead of just queuing silently --------------
  // A plain form submit would flash "queued, check back later" and reload the
  // page. Instead: show the button actively scanning, then poll until the
  // scan the server just queued actually finishes (a NEW last_scan.id shows
  // up), and surface the result immediately. The scan itself still runs in
  // the background scheduler thread, same as before — never inside this
  // request — this only changes how the wait is shown to the user.
  (function () {
    var POLL_MS = 1200;
    // A full-subnet ARP sweep on this machine/network measured ~24-30s (mostly
    // Npcap packet-injection time for every address in the /24, not something
    // a UI fix can shrink) — plus this click may have to wait out a scan cycle
    // that was already in progress when it landed. 90s gives real headroom
    // above that worst case before calling it "taking longer than usual".
    var TIMEOUT_MS = 90000;

    function notice(text, category) {
      var main = document.querySelector("main.app-content, .auth-main") || document.body;
      var box = document.createElement("div");
      box.className = "alert alert-" + (category || "success") + " alert-dismissible fade show";
      box.setAttribute("role", "alert");
      box.textContent = text;
      var btn = document.createElement("button");
      btn.type = "button"; btn.className = "btn-close"; btn.setAttribute("data-bs-dismiss", "alert");
      box.appendChild(btn);
      main.insertBefore(box, main.firstChild);
      if (category !== "danger") {
        setTimeout(function () {
          if (!box.isConnected) return;
          if (window.bootstrap && bootstrap.Alert) bootstrap.Alert.getOrCreateInstance(box).close();
          else box.remove();
        }, 6000);
      }
    }

    function getSummary() {
      return fetch("/api/summary", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; });
    }

    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (!form || form.id !== "scan-now-form") return;
      e.preventDefault();

      var btn = document.getElementById("scan-now-btn");
      if (!btn || btn.disabled) return;         // a scan is already in flight
      var original = btn.innerHTML;
      btn.disabled = true;

      // A real sweep commonly takes 20-30s here, not a flash — show elapsed
      // time so the button visibly ticks rather than sitting on a static
      // "Scanning…" that reads as stuck once more than a couple of seconds pass.
      var clickedAt = Date.now();
      function renderScanning() {
        var secs = Math.floor((Date.now() - clickedAt) / 1000);
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span> Scanning… ' + secs + 's';
      }
      renderScanning();
      var tickId = setInterval(renderScanning, 1000);

      function restore() { clearInterval(tickId); btn.disabled = false; btn.innerHTML = original; }

      getSummary().then(function (before) {
        var baselineId = before && before.last_scan ? before.last_scan.id : null;

        fetch(form.action, {
          method: "POST", body: new FormData(form), credentials: "same-origin",
          headers: { "X-Requested-With": "XMLHttpRequest" },
        }).then(function (resp) {
          return resp.ok ? resp.json() : { queued: false };
        }).then(function (ack) {
          if (!ack.queued) {
            restore();
            notice("Scan could not be started — the scheduler is not running.", "warning");
            return;
          }

          var startedAt = Date.now();
          (function poll() {
            if (Date.now() - startedAt > TIMEOUT_MS) {
              restore();
              notice("The scan is taking longer than usual — it's still running in the background.", "warning");
              return;
            }
            getSummary().then(function (data) {
              var ls = data && data.last_scan;
              var finished = ls && ls.id != null && ls.id !== baselineId;
              if (!finished) { setTimeout(poll, POLL_MS); return; }
              restore();
              var online = data.counts ? data.counts.online : null;
              notice(online != null
                ? "Scan complete — " + online + " device(s) online right now."
                : "Scan complete.", "success");
              // Let any page-local pollers (the dashboard's live.js) pick up
              // the fresh data on their own next tick; no page reload needed.
            });
          })();
        }).catch(function () {
          restore();
          notice("Could not reach the server to start the scan.", "danger");
        });
      });
    });
  })();

  // --- Flash messages: dismiss themselves ------------------------------------
  // Success/info/warning notices fade out on their own; ERRORS (alert-danger)
  // stay until the user closes them, so a failure is never missed.
  var FLASH_MS = 6000;
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".alert-dismissible").forEach(function (box) {
      if (box.classList.contains("alert-danger")) return;      // keep errors
      setTimeout(function () {
        if (!box.isConnected) return;
        if (window.bootstrap && bootstrap.Alert) {
          bootstrap.Alert.getOrCreateInstance(box).close();     // animated fade
        } else {
          box.remove();
        }
      }, FLASH_MS);
    });
  });

  // --- Pagination: stay where you are -----------------------------------------
  // Paging reloads the page with ?page=N, which normally jumps to the top.
  // Remember the scroll position on click and restore it after the reload.
  var SCROLL_KEY = "pwnm:scroll:";
  document.addEventListener("click", function (e) {
    var link = e.target.closest && e.target.closest("[data-keep-scroll] a");
    if (!link || link.classList.contains("disabled")) return;
    try { sessionStorage.setItem(SCROLL_KEY + location.pathname, String(window.scrollY)); }
    catch (err) { /* private mode: fall back to the normal jump */ }
  }, true);

  document.addEventListener("DOMContentLoaded", function () {
    var key = SCROLL_KEY + location.pathname, y;
    try { y = sessionStorage.getItem(key); sessionStorage.removeItem(key); } catch (err) { return; }
    if (y === null || y === undefined) return;
    if (history.scrollRestoration) history.scrollRestoration = "manual";
    window.scrollTo(0, parseInt(y, 10) || 0);
  });

  // --- Show / hide password: every <input type="password"> gets an eye button ---
  function addPasswordToggle(input) {
    if (input.dataset.pwToggle) return;            // never wrap twice
    input.dataset.pwToggle = "1";

    var group = document.createElement("div");
    group.className = "input-group flex-nowrap pw-group" +
      (input.classList.contains("form-control-sm") ? " input-group-sm" : "");
    // Compact fields carry an inline width: move it to the group so the button fits.
    if (input.style.width) {
      group.style.width = "calc(" + input.style.width + " + 2.4rem)";
      input.style.width = "";
    }
    input.parentNode.insertBefore(group, input);
    group.appendChild(input);

    var btn = document.createElement("button");
    btn.type = "button";                              // never submits the form
    btn.className = "btn pw-toggle";
    btn.setAttribute("aria-label", "Show password");
    btn.setAttribute("aria-pressed", "false");
    btn.title = "Show password";
    btn.innerHTML = '<i class="bi bi-eye" aria-hidden="true"></i>';
    group.appendChild(btn);

    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.innerHTML = '<i class="bi ' + (show ? "bi-eye-slash" : "bi-eye") + '" aria-hidden="true"></i>';
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
      btn.title = show ? "Hide password" : "Show password";
      input.focus();
    });
  }

  // Before submit, flip any revealed field back to password so browsers don't
  // offer to save it as plain text or autocomplete it into other fields.
  document.addEventListener("submit", function (e) {
    var revealed = e.target.querySelectorAll ? e.target.querySelectorAll('input[data-pw-toggle="1"][type="text"]') : [];
    revealed.forEach(function (i) { i.type = "password"; });
  });

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('input[type="password"]').forEach(addPasswordToggle);
  });
})();
