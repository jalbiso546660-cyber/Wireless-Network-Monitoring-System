"""
web/routes/devices.py
=====================
Device inventory: filtered table (all roles), detail page with access-history
timeline (all roles), and admin-only actions (authorize / block / label).

The POST actions are admin-only via @role_required('admin') and CSRF-protected
by the global before_request hook in web/security.py.
"""
from __future__ import annotations

import math

from flask import (Blueprint, abort, flash, redirect, request, render_template,
                   url_for)
from flask_login import current_user, login_required

from data import repos
from web.routes.auth import role_required

devices_bp = Blueprint("devices", __name__)

_VALID_STATUS = {"authorized", "unauthorized", "blocked"}
_PER_PAGE = 5
# Access-history page size. Viewers get a smaller page (19) than monitor/admin
# (23) per the UI spec — same list, just a shorter page for the read-only role.
_HISTORY_PER_PAGE = 23
_HISTORY_PER_PAGE_VIEWER = 18
_ALERTS_PER_PAGE = 10    # 'Related alerts' on the device detail page


def _history_per_page() -> int:
    return _HISTORY_PER_PAGE_VIEWER if current_user.role == "viewer" else _HISTORY_PER_PAGE


@devices_bp.route("/devices")
@login_required
def index():
    # Filters from the query string (validated against known values).
    status = request.args.get("status") or None
    if status not in _VALID_STATUS:
        status = None
    online_arg = request.args.get("online")   # 'online' | 'offline' | None
    online = True if online_arg == "online" else (False if online_arg == "offline" else None)

    # Pagination.
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    total = repos.count_devices_filtered(status=status, online=online)
    total_pages = max(1, math.ceil(total / _PER_PAGE))
    page = min(page, total_pages)
    offset = (page - 1) * _PER_PAGE
    devices = repos.query_devices(status=status, online=online,
                                  limit=_PER_PAGE, offset=offset)

    filter_args = {}
    if status:
        filter_args["status"] = status
    if online_arg in ("online", "offline"):
        filter_args["online"] = online_arg

    return render_template("devices.html", devices=devices,
                           f_status=status, f_online=online_arg,
                           page=page, total_pages=total_pages, total=total,
                           per_page=_PER_PAGE, filter_args=filter_args)


@devices_bp.route("/devices/<int:device_id>")
@login_required
def detail(device_id: int):
    device = repos.get_device(device_id)
    if not device:
        abort(404)

    # Paginated access history.
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    history_per_page = _history_per_page()
    total = repos.count_access_history(device_id)
    total_pages = max(1, math.ceil(total / history_per_page))
    page = min(page, total_pages)
    history = repos.get_device_history(
        device_id, limit=history_per_page, offset=(page - 1) * history_per_page)

    # For a blocked device, show the router MAC-filter instruction (the system
    # does NOT block traffic itself — by design).
    mac_filter = repos.generate_mac_filter(device_id) if device["status"] == "blocked" else None

    # Paginated related alerts. Its page lives in its OWN query arg (apage) so
    # paging alerts never resets the access-history page, and vice versa.
    apage = request.args.get("apage", 1, type=int)
    if apage < 1:
        apage = 1
    alerts_total = repos.count_device_alerts(device_id)
    alerts_pages = max(1, math.ceil(alerts_total / _ALERTS_PER_PAGE))
    apage = min(apage, alerts_pages)
    alerts = repos.get_device_alerts(device_id, limit=_ALERTS_PER_PAGE,
                                     offset=(apage - 1) * _ALERTS_PER_PAGE)

    ip_history = repos.get_ip_history(device_id)
    return render_template("device_detail.html", device=device, history=history,
                           mac_filter=mac_filter, alerts=alerts,
                           ip_history=ip_history, page=page,
                           total_pages=total_pages, total=total,
                           per_page=history_per_page,
                           apage=apage, alerts_pages=alerts_pages,
                           alerts_total=alerts_total,
                           alerts_per_page=_ALERTS_PER_PAGE)


# --- admin actions (POST, CSRF-protected, admin only) ----------------------
def _back_to_device(device_id: int):
    nxt = request.form.get("next")
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect(url_for("devices.detail", device_id=device_id))


@devices_bp.route("/devices/<int:device_id>/authorize", methods=["POST"])
@role_required("admin")
def authorize(device_id: int):
    if not repos.get_device(device_id):
        abort(404)
    repos.authorize_device(device_id, current_user.id)
    flash("Device marked AUTHORIZED.", "success")
    return _back_to_device(device_id)


@devices_bp.route("/devices/<int:device_id>/block", methods=["POST"])
@role_required("admin")
def block(device_id: int):
    device = repos.get_device(device_id)
    if not device:
        abort(404)
    reason = (request.form.get("reason") or "").strip() or None
    repos.block_device(device_id, current_user.id, reason)
    # 'blocked' is an authorization STATE — we do NOT send deauth/traffic blocks.
    flash(f"Device FLAGGED. Apply a MAC filter for {device['mac_address']} "
          f"on the router; every reappearance will raise a critical alert.",
          "danger")
    return _back_to_device(device_id)


@devices_bp.route("/devices/<int:device_id>/merge", methods=["POST"])
@role_required("admin")
def merge(device_id: int):
    """Fold a duplicate device (its MAC) into this one (Module 3.3) — mitigates
    MAC randomization creating apparent new devices."""
    if not repos.get_device(device_id):
        abort(404)
    dup_mac = (request.form.get("duplicate_mac") or "").strip().lower()
    dup = repos.get_device_by_mac(dup_mac) if dup_mac else None
    if not dup:
        flash("No device found with that MAC to merge.", "danger")
    elif dup["id"] == device_id:
        flash("Cannot merge a device into itself.", "danger")
    elif repos.merge_devices(device_id, dup["id"]):
        flash(f"Merged {dup_mac} into this device; its history was preserved.",
              "success")
    else:
        flash("Merge failed.", "danger")
    return _back_to_device(device_id)


@devices_bp.route("/devices/<int:device_id>/label", methods=["POST"])
@role_required("admin")
def label(device_id: int):
    if not repos.get_device(device_id):
        abort(404)
    new_label = (request.form.get("label") or "").strip()
    repos.set_device_label(device_id, new_label or None)
    flash("Device label updated.", "success")
    return _back_to_device(device_id)
