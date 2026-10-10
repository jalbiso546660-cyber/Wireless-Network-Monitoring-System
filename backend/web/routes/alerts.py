"""
web/routes/alerts.py  — Module 6: Alert & Notification

Alerts view (read for all roles), an alert-detail page with the triggering
evidence, and the acknowledge/resolve lifecycle (monitor + admin). Alerts are
produced by the detection engine (detection/*) during each scan cycle.
"""
from __future__ import annotations

import math

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from data import repos
from web.routes.auth import role_required

alerts_bp = Blueprint("alerts", __name__)

_VALID_STATUS = {"new", "acknowledged", "resolved"}
_VALID_SEVERITY = {"low", "medium", "high", "critical"}
_PER_PAGE = 5


def _safe_next(default: str) -> str:
    """Only follow a local path in ?next= (open-redirect guard)."""
    nxt = request.form.get("next")
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return default


@alerts_bp.route("/alerts")
@login_required
def index():
    status = request.args.get("status") or None
    if status not in _VALID_STATUS:
        status = None
    severity = request.args.get("severity") or None
    if severity not in _VALID_SEVERITY:
        severity = None
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    try:
        total = repos.count_alerts(severity=severity, status=status)
        total_pages = max(1, math.ceil(total / _PER_PAGE))
        page = min(page, total_pages)
        alerts = repos.get_alerts(severity=severity, status=status,
                                  limit=_PER_PAGE, offset=(page - 1) * _PER_PAGE)
        by_severity = repos.alerts_by_severity()
        open_count = repos.count_open_alerts()
    except Exception:
        alerts, by_severity, open_count, total, total_pages, page = [], {}, 0, 0, 1, 1

    filter_args = {}
    if status:
        filter_args["status"] = status
    if severity:
        filter_args["severity"] = severity
    return render_template("alerts.html", alerts=alerts, f_status=status,
                           f_severity=severity, by_severity=by_severity,
                           open_count=open_count, page=page,
                           total_pages=total_pages, total=total,
                           per_page=_PER_PAGE, filter_args=filter_args)


@alerts_bp.route("/alerts/<int:alert_id>")
@login_required
def detail(alert_id: int):
    """Alert detail with its triggering evidence + the device record (Module 6)."""
    view = repos.get_alert_detail(alert_id)
    if not view:
        abort(404)
    return render_template("alert_detail.html", **view)


@alerts_bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@role_required("monitor")     # monitor + admin
def acknowledge(alert_id: int):
    if not repos.get_alert(alert_id):
        abort(404)
    repos.acknowledge_alert(alert_id, current_user.id)
    flash("Alert acknowledged.", "success")
    return redirect(_safe_next(url_for("alerts.index")))


@alerts_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@role_required("monitor")     # monitor + admin
def resolve(alert_id: int):
    if not repos.get_alert(alert_id):
        abort(404)
    note = (request.form.get("note") or "").strip() or None
    repos.resolve_alert(alert_id, current_user.id, note)
    flash("Alert resolved.", "success")
    return redirect(_safe_next(url_for("alerts.index")))
