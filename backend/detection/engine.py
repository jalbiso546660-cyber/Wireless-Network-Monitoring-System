"""
detection/engine.py
===================
Rule Engine (Module 5.4). Runs every rule for one scan, collects the alert
specs, DE-DUPLICATES them against recent alerts, and writes the survivors.

evaluate() NEVER raises — a detection failure must not break the scan loop. It
returns the ids of the alerts it created (handy for tests/logging).

EVERY threshold is read from the settings table here and passed into the pure
rules — there is no detection constant in code (project requirement). Network
access (the gateway MAC, the sniffer state) is passed in by the caller, so this
module stays unit-testable without touching the network.
"""
from __future__ import annotations

import logging
from datetime import datetime

from data import repos
from detection import rules

log = logging.getLogger(__name__)

GATEWAY_BASELINE_KEY = "gateway_mac_baseline"


# --- helpers -----------------------------------------------------------------
def _dv(dev: dict) -> dict:
    return {
        "id": dev["id"],
        "mac": dev["mac_address"],
        "vendor": dev.get("vendor"),
        "last_ip": dev.get("last_ip"),
        "status": dev.get("status"),
        "open_ports": dev.get("open_ports"),
    }


def _parse_ports(value) -> list[int]:
    if not value:
        return []
    out = []
    for tok in str(value).split(","):
        tok = tok.strip()
        if tok.isdigit():
            out.append(int(tok))
    return out


def is_duplicate(rule_code: str, device_id: int | None,
                 window_seconds: int) -> bool:
    """Module 6.2 — True if an equivalent alert already exists inside the
    rate-limit window (prevents repetitive alerting)."""
    return repos.recent_alert_exists(rule_code, device_id, window_seconds)


def _emit(spec: dict | None, window: int, created: list) -> None:
    if not spec:
        return
    if is_duplicate(spec["rule_code"], spec.get("device_id"), window):
        return
    aid = repos.insert_alert(spec["rule_code"], spec["severity"], spec["title"],
                             spec.get("detail"), spec.get("device_id"))
    created.append(aid)


def _check_gateway(gateway: dict, window: int, created: list) -> None:
    """Learn the gateway MAC on first sight; alert if it later changes."""
    ip = gateway.get("ip")
    mac = (gateway.get("mac") or "").lower()
    if not ip or not mac:
        return
    baseline = repos.get_setting(GATEWAY_BASELINE_KEY)
    if not baseline:
        repos.set_setting(GATEWAY_BASELINE_KEY, mac)      # learn, don't alert
        return
    dev = repos.get_device_by_ip(ip)
    _emit(rules.rule_arp_spoof(ip, mac, str(baseline),
                               dev["id"] if dev else None), window, created)


# --- the rule engine ---------------------------------------------------------
def evaluate(scan_result: dict, sniffer_state=None, gateway: dict | None = None,
             now: datetime | None = None) -> list[int]:
    """Run all rules for one scan `scan_result`. Returns created alert ids."""
    created: list[int] = []
    try:
        now = now or datetime.now()

        # --- every threshold comes from settings (no constants) -------------
        dedup = repos.get_int_setting("alert_dedup_seconds", 300)
        unauth_window = repos.get_int_setting("unauth_return_rate_limit_seconds", 3600)
        q_start = str(repos.get_setting("quiet_hours_start", "00:00"))
        q_end = str(repos.get_setting("quiet_hours_end", "05:00"))
        churn_thr = repos.get_int_setting("ipchurn_distinct_ips", 3)
        churn_min = repos.get_int_setting("ipchurn_window_minutes", 10)
        watch = set(_parse_ports(repos.get_setting("service_watch_ports", "")))

        joined = scan_result.get("joined", [])
        present = scan_result.get("present", [])
        new_macs = scan_result.get("new_devices", [])
        seen = list(dict.fromkeys(joined + present))      # every device this scan

        # --- 5.2 unauthorized new (brand-new MAC) ---------------------------
        for mac in new_macs:
            dev = repos.get_device_by_mac(mac)
            if dev:
                _emit(rules.rule_unauth_new(_dv(dev)), dedup, created)

        # --- 5.2 return / off-hours: only on JOIN transitions ---------------
        for mac in joined:
            dev = repos.get_device_by_mac(mac)
            if not dev:
                continue
            dv = _dv(dev)
            _emit(rules.rule_unauth_return(dv), unauth_window, created)
            _emit(rules.rule_off_hours_join(dv, now, q_start, q_end), dedup, created)

        # --- 5.2/5.3 present-based: blocked, ip churn, service anomaly -------
        for mac in seen:
            dev = repos.get_device_by_mac(mac)
            if not dev:
                continue
            dv = _dv(dev)
            _emit(rules.rule_blocked_seen(dv), dedup, created)
            churn = repos.distinct_ip_count(dev["id"], churn_min)
            _emit(rules.rule_ip_churn(dv, churn, churn_thr, churn_min), dedup, created)
            ports = _parse_ports(dev.get("open_ports"))
            if ports and watch:
                _emit(rules.rule_service_anomaly(dv, ports, watch), dedup, created)

        # --- 5.3 ARP spoof: gateway MAC change ------------------------------
        if gateway:
            _check_gateway(gateway, dedup, created)

        # --- 5.3 sniffer-based: ARP conflicts + port scan -------------------
        if sniffer_state is not None:
            arp_window = repos.get_int_setting("arp_conflict_window_seconds", 120)
            for ip, macs in sniffer_state.arp.conflicts(arp_window):
                dev = repos.get_device_by_ip(ip)
                _emit(rules.rule_arp_conflict(ip, macs, dev["id"] if dev else None),
                      dedup, created)

            threshold = repos.get_int_setting("portscan_port_threshold", 15)
            window = repos.get_int_setting("portscan_window_seconds", 60)
            for src, count in sniffer_state.ports.offenders(threshold, window):
                dev = repos.get_device_by_ip(src)
                _emit(rules.rule_port_scan(src, count, threshold,
                                           dev["id"] if dev else None), dedup, created)

        if created:
            log.info("detection: created %d alert(s) for scan #%s",
                     len(created), scan_result.get("scan_id"))
    except Exception:
        log.exception("evaluate failed (non-fatal; scan loop continues)")
    return created
