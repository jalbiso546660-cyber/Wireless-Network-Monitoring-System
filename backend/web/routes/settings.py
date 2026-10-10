"""
web/routes/settings.py  — Module 9: System Configuration (admin-only)

Lets the administrator tune detection thresholds and scanning behaviour live,
without editing code or restarting the app. Every value is validated in the data
layer (repos.validate_setting) BEFORE it is stored, so an invalid threshold can
never disable detection.

Layering note: this route imports core.interfaces (psutil only — NO Scapy), so
the web layer stays Scapy-free. It never imports the scheduler; to reschedule
the scan job live it calls the callable the scheduler published on
app.config['APPLY_SCAN_INTERVAL'].
"""
from __future__ import annotations

import shutil

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)
from flask_login import current_user

from core import interfaces
from data import db, repos
from web.routes.auth import role_required

# url_prefix keeps the stable /admin/settings URL the nav and tests already use.
settings_bp = Blueprint("settings", __name__, url_prefix="/admin")

# Detection-engine internal key (mirrors detection.engine.GATEWAY_BASELINE_KEY);
# kept as a literal so the web layer need not import the detection package.
_GATEWAY_BASELINE_KEY = "gateway_mac_baseline"


def _system_health() -> dict:
    """A live capability/health snapshot for the admin panel: is each moving
    part actually available? (DB reachable, scan scheduler running, passive
    sniffer capturing, nmap profiler installed.)"""
    cfg = current_app.config
    sniffer = cfg.get("SNIFFER_STATE")
    return {
        "database": db.ping(),
        "scanner": cfg.get("SCHEDULER") is not None,
        "sniffer": sniffer is not None,
        "nmap": shutil.which("nmap") is not None,
    }


def _view_models() -> list[dict]:
    """Settings grouped into plain-English sections for the form.

    Only user-editable keys (those in SETTING_SPECS) are shown — internal keys
    such as gateway_mac_baseline have their own controls and never appear as a
    raw editable field. Help text comes from the spec (falls back to the DB
    description)."""
    stored = {r["setting_key"]: r for r in repos.list_settings()}
    groups = []
    for g in repos.SETTING_GROUPS:
        items = []
        for key, spec in repos.SETTING_SPECS.items():
            if spec.get("group") != g["key"] or key not in stored:
                continue
            row = stored[key]
            items.append({
                "key": key,
                "value": row["setting_value"],
                "label": spec.get("label", key),
                "help": spec.get("help") or row.get("description") or "",
                "unit": spec.get("unit", ""),
                "kind": spec.get("kind", "text"),
                "min": spec.get("min", ""),
                "max": spec.get("max", ""),
            })
        if items:
            groups.append({**g, "items": items})
    return groups


def select_interface(name: str) -> str | None:
    """Module 9.3 — store the chosen adapter and its DERIVED subnet.

    Looks the adapter up via core.interfaces (psutil) and, if found, stores both
    monitor_interface and the CIDR subsequent scans will sweep. Returns the
    derived subnet, or None if the name matched no live adapter (the name is
    still stored so the operator sees their choice)."""
    match = next((i for i in interfaces.list_interfaces() if i["name"] == name), None)
    repos.set_setting("monitor_interface", name)
    if match:
        repos.set_setting("monitor_subnet", match["subnet_cidr"])
        return match["subnet_cidr"]
    return None


@settings_bp.route("/settings")
@role_required("admin")
def index():
    return render_template("admin_settings.html", groups=_view_models(),
                           setting_label=repos.setting_label,
                           interfaces=interfaces.list_interfaces(),
                           audit=repos.recent_setting_changes(10),
                           health=_system_health(),
                           gateway_baseline=repos.get_setting(_GATEWAY_BASELINE_KEY))


@settings_bp.route("/settings/reset-baseline", methods=["POST"])
@role_required("admin")
def reset_baseline():
    """Clear the learned gateway-MAC baseline so the next scan re-learns it.
    Use after a legitimate router/gateway change to stop false ARP_SPOOF alerts
    (trust-on-first-use: the first scan after reset re-establishes the baseline)."""
    old = repos.get_setting(_GATEWAY_BASELINE_KEY)
    repos.set_setting(_GATEWAY_BASELINE_KEY, "")
    repos.record_setting_change(_GATEWAY_BASELINE_KEY, old, "(reset)", current_user.id)
    flash("Gateway ARP baseline cleared — it will be re-learned on the next scan.",
          "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/settings", methods=["POST"])
@role_required("admin")
def save():
    # Validate every submitted, known setting first; store nothing on any error
    # so a partial/invalid save can't leave detection in a broken state.
    errors: list[str] = []
    updates: dict[str, object] = {}
    for row in repos.list_settings():
        key = row["setting_key"]
        if key not in request.form:
            continue
        ok, result = repos.validate_setting(key, request.form.get(key))
        if ok:
            updates[key] = result
        else:
            errors.append(result)

    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("settings.index"))

    old = {r["setting_key"]: r["setting_value"] for r in repos.list_settings()}
    for key, value in updates.items():
        repos.set_setting(key, value)
        repos.record_setting_change(key, old.get(key), value, current_user.id)

    # Apply a new scan interval to the running job immediately (no restart).
    if "scan_interval_seconds" in updates:
        apply = current_app.config.get("APPLY_SCAN_INTERVAL")
        if apply:
            apply(int(updates["scan_interval_seconds"]))

    flash(f"Saved {len(updates)} setting(s). Changes take effect immediately.",
          "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/settings/interface", methods=["POST"])
@role_required("admin")
def choose_interface():
    """Module 9.3 UI — pick a detected adapter; its subnet is derived + stored."""
    name = (request.form.get("interface") or "").strip()
    if not name:
        flash("Choose an interface.", "danger")
        return redirect(url_for("settings.index"))
    old_iface = repos.get_setting("monitor_interface")
    old_subnet = repos.get_setting("monitor_subnet")
    subnet = select_interface(name)
    repos.record_setting_change("monitor_interface", old_iface, name, current_user.id)
    if subnet:
        repos.record_setting_change("monitor_subnet", old_subnet, subnet, current_user.id)
    if subnet:
        flash(f"Monitoring '{name}' — subnet set to {subnet}.", "success")
    else:
        flash(f"Interface '{name}' not found among live adapters; stored the "
              f"name but left the subnet unchanged.", "warning")
    return redirect(url_for("settings.index"))
