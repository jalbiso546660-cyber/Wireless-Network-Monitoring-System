"""
web/routes/dashboard.py
=======================
Dashboard page + JSON polling APIs + the non-blocking manual scan trigger.

The APIs return plain JSON that live.js polls every 5s. /scan/now does NOT run a
scan in the request — it asks the scheduler to run one and returns immediately.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from data import db, repos
from web.routes.auth import role_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/healthz")
def healthz():
    """Liveness/readiness probe (public, no auth) for monitoring/uptime checks.
    Deliberately minimal — only whether the app is up and the DB reachable, so
    it leaks nothing sensitive. 200 = healthy, 503 = degraded (DB down)."""
    db_up = db.ping()
    payload = {"status": "ok" if db_up else "degraded",
               "database": "up" if db_up else "down",
               "time": datetime.now().isoformat(timespec="seconds")}
    return jsonify(payload), (200 if db_up else 503)


def _iso(dt) -> str | None:
    return dt.isoformat(sep=" ", timespec="seconds") if dt else None


def _seconds_ago(dt) -> int | None:
    return int((datetime.now() - dt).total_seconds()) if dt else None


def _device_json(d: dict) -> dict:
    """Shape a device row for the API (JSON-safe, only what the UI needs)."""
    return {
        "id": d["id"],
        "mac": d["mac_address"],
        "label": d.get("device_label"),
        "ip": d.get("last_ip"),
        "hostname": d.get("hostname"),
        "vendor": d.get("vendor"),
        "status": d["status"],
        "is_online": bool(d["is_online"]),
        "last_seen": _iso(d.get("last_seen")),
        "last_seen_ago": _seconds_ago(d.get("last_seen")),
    }


def _last_scan_block() -> dict:
    scan = repos.last_finished_scan()
    if not scan:
        return {"id": None, "finished_at": None, "seconds_ago": None}
    return {"id": scan["id"], "finished_at": _iso(scan["finished_at"]),
            "seconds_ago": _seconds_ago(scan["finished_at"])}


def _activity_json(a: dict) -> dict:
    """Shape one access-log row for the live activity feed (JSON-safe)."""
    return {
        "event": a["event"],
        "who": a.get("device_label") or a.get("mac_address"),
        "device_id": a.get("device_id"),
        "ip": a.get("ip_address"),
        "ago": _seconds_ago(a.get("seen_at")),
    }


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    """render_dashboard (Module 7) — assembles the panels; the template shows
    role-appropriate controls via current_user.role."""
    devices = [_device_json(d) for d in repos.get_online_devices()]
    summary = repos.get_summary()
    return render_template("dashboard.html", devices=devices,
                           counts=summary["counts"],
                           open_alerts=summary["open_alerts"],
                           last_scan=_last_scan_block(),
                           activity=repos.get_activity_feed(limit=8))


@dashboard_bp.route("/activity")
@login_required
def activity():
    """Access-tracking view (Module 4): the presence timeline (4.1) + network
    occupancy (4.2). Date-selectable; charts are drawn by charts.js."""
    sel_date = request.args.get("date") or datetime.now().date().isoformat()
    return render_template("activity.html", sel_date=sel_date)


@dashboard_bp.route("/api/devices")
@login_required
def api_devices():
    """Live device feed for polling. scope=online (default) or all."""
    scope = request.args.get("scope", "online")
    rows = repos.get_online_devices() if scope == "online" else repos.list_devices()
    return jsonify({
        "server_time": _iso(datetime.now()),
        "last_scan": _last_scan_block(),
        "devices": [_device_json(d) for d in rows],
    })


@dashboard_bp.route("/api/netstats")
@login_required
def api_netstats():
    """Live network throughput (download/upload) + gateway ping for the
    dashboard. Values come from a cached background sampler (core.netstats),
    so this handler never blocks on the ping subprocess. psutil-only — the web
    layer stays Scapy-free (same pattern as importing core.interfaces)."""
    from core import netstats
    return jsonify(netstats.snapshot())


@dashboard_bp.route("/api/summary")
@login_required
def api_summary():
    """Stat-tile counts + the activity feed (polled). Charts are served
    separately by /api/charts/* and drawn by charts.js."""
    summary = repos.get_summary()
    return jsonify({
        "counts": summary["counts"],
        "open_alerts": summary["open_alerts"],   # new + acknowledged
        "last_scan": _last_scan_block(),
        "activity": [_activity_json(a) for a in repos.get_activity_feed(8)],
    })


def _back_to_caller():
    """Send the user back to the page they pressed the button on (the sidebar
    button appears on every page), instead of always jumping to the dashboard.

    Only same-site paths are followed — an absolute URL, a //host, or a
    backslash trick falls back to the dashboard (open-redirect protection)."""
    ref = request.referrer or ""
    if ref:
        parts = urlparse(ref)
        if not parts.netloc or parts.netloc == request.host:
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            if (path.startswith("/") and not path.startswith("//")
                    and "\\" not in path):
                return redirect(path)
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/scan/now", methods=["POST"])
@role_required("monitor")     # monitor + admin
def scan_now():
    """Enqueue a scan on the scheduler and return immediately (never scans in
    the request thread — scans always run in the APScheduler job, not here).

    AJAX callers (sent by the sidebar's "Scan now" button, identified by the
    X-Requested-With header) get a tiny JSON ack instead of a redirect. The
    page then polls /api/summary and shows the scan actually running and
    finishing in real time, instead of a static "check back later" message.
    A plain (non-JS) form submit still gets the classic flash + redirect.
    """
    trigger = current_app.config.get("SCAN_TRIGGER")
    queued = bool(trigger and trigger(user_id=current_user.id))

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"queued": queued})

    if queued:
        flash("Scan queued — results will appear on the next refresh.", "info")
    else:
        flash("Scan could not be queued (the scheduler is not running).", "warning")
    return _back_to_caller()
