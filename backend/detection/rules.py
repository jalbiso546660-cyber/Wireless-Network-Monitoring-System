"""
detection/rules.py
==================
Pure detection rules (Module 5.2 + 5.3). NO database, NO network, NO Flask —
each rule takes plain data and returns an alert spec dict (or None), so every
rule is unit-testable with synthetic input and exact threshold boundaries.

An alert spec is:  {"rule_code", "severity", "title", "detail", "device_id"}

The engine (detection/engine.py) supplies real device/setting data, applies
de-duplication, and writes the survivors to the `alerts` table. Every threshold
these rules use is passed IN by the engine, which read it from the settings
table — never a constant here.

Rules
-----
  rule_unauth_new       high      a MAC never recorded before joins
  rule_unauth_return    medium    a known-unauthorized device returns
  rule_blocked_seen     critical  a device marked 'blocked' is present
  rule_arp_spoof        critical  the gateway's MAC changed from its baseline
  rule_arp_conflict     critical  two MACs claim one IP (ARP-poisoning tell)
  rule_port_scan        high      one source hit >= N distinct ports in a window
  rule_off_hours_join   medium    a join fell inside quiet hours
  rule_ip_churn         medium    one MAC used several IPs within a short window
  rule_service_anomaly  low       a device exposes watched/sensitive ports
"""
from __future__ import annotations

from datetime import datetime, time

# Severities (must match the alerts.severity ENUM: low/medium/high/critical).
SEV_UNAUTH_NEW = "high"        # spec: a brand-new/unauthorized MAC is HIGH
SEV_UNAUTH_RETURN = "medium"
SEV_BLOCKED = "critical"
SEV_ARP = "critical"
SEV_PORTSCAN = "high"
SEV_QUIET = "medium"
SEV_IP_CHURN = "medium"
SEV_SERVICE = "low"


def _alert(rule_code: str, severity: str, title: str,
           detail: str | None = None, device_id: int | None = None) -> dict:
    return {"rule_code": rule_code, "severity": severity, "title": title,
            "detail": detail, "device_id": device_id}


# --- 5.2 Unauthorized device rules ------------------------------------------
def rule_unauth_new(device: dict) -> dict:
    """A MAC seen for the very first time (brand-new device joining)."""
    vendor = device.get("vendor") or "unknown vendor"
    return _alert(
        "UNAUTH_NEW", SEV_UNAUTH_NEW,
        f"New/unknown device joined the network: {device['mac']}",
        detail=f"{device['mac']} ({vendor}) at {device.get('last_ip') or '?'}",
        device_id=device.get("id"))


def rule_unauth_return(device: dict) -> dict | None:
    """A known 'unauthorized' device reappearing. None if it isn't unauthorized.
    The engine rate-limits this to one alert per device per hour."""
    if device.get("status") != "unauthorized":
        return None
    return _alert(
        "UNAUTH_RETURN", SEV_UNAUTH_RETURN,
        f"Unauthorized device on the network: {device['mac']}",
        detail=f"{device['mac']} ({device.get('vendor') or '?'}) "
               f"at {device.get('last_ip') or '?'}",
        device_id=device.get("id"))


def rule_blocked_seen(device: dict) -> dict | None:
    """A device the admin marked 'blocked' is present — always critical."""
    if device.get("status") != "blocked":
        return None
    return _alert(
        "BLOCKED_SEEN", SEV_BLOCKED,
        f"FLAGGED device present: {device['mac']}",
        detail=f"Flagged device {device['mac']} is on the network at "
               f"{device.get('last_ip') or '?'}. Verify the router MAC filter.",
        device_id=device.get("id"))


# --- 5.3 Suspicious activity rules ------------------------------------------
def rule_arp_spoof(gateway_ip: str, current_mac: str | None,
                   baseline_mac: str | None,
                   device_id: int | None = None) -> dict | None:
    """Gateway MAC differs from its learned baseline. None if no baseline yet or
    the MAC is unchanged/unknown."""
    if not baseline_mac or not current_mac:
        return None
    if current_mac.lower() == baseline_mac.lower():
        return None
    return _alert(
        "ARP_SPOOF", SEV_ARP,
        "Gateway MAC changed — possible ARP spoofing",
        detail=f"Gateway {gateway_ip}: baseline {baseline_mac} -> now {current_mac}.",
        device_id=device_id)


def rule_arp_conflict(ip: str, macs: list[str],
                      device_id: int | None = None) -> dict | None:
    """Two or more MACs claim the same IP within the window (ARP poisoning).
    None if fewer than two MACs."""
    macs = [m for m in dict.fromkeys(macs) if m]      # de-dupe, keep order
    if len(macs) < 2:
        return None
    return _alert(
        "ARP_SPOOF", SEV_ARP,
        f"Multiple MACs claim {ip} — possible ARP spoofing",
        detail=f"{ip} was claimed by {len(macs)} MACs: {', '.join(macs)}.",
        device_id=device_id)


def rule_port_scan(src_ip: str, port_count: int, threshold: int,
                   device_id: int | None = None) -> dict:
    return _alert(
        "PORT_SCAN", SEV_PORTSCAN,
        f"Possible port scan from {src_ip}",
        detail=f"{src_ip} contacted {port_count} distinct ports "
               f"(threshold {threshold}).",
        device_id=device_id)


# --- quiet hours -------------------------------------------------------------
def parse_hhmm(value: str) -> time:
    """'HH:MM' -> datetime.time. Raises ValueError on bad input."""
    hh, mm = value.strip().split(":")
    return time(int(hh), int(mm))


def within_quiet_hours(now_t: time, start_t: time, end_t: time) -> bool:
    """True if now_t is in [start, end). Handles windows that wrap midnight
    (e.g. 22:00-05:00). A zero-length window (start == end) is never inside."""
    if start_t == end_t:
        return False
    if start_t < end_t:
        return start_t <= now_t < end_t
    return now_t >= start_t or now_t < end_t          # wraps past midnight


def rule_off_hours_join(device: dict, now: datetime,
                        start_hhmm: str, end_hhmm: str) -> dict | None:
    try:
        start_t, end_t = parse_hhmm(start_hhmm), parse_hhmm(end_hhmm)
    except (ValueError, AttributeError):
        return None
    if not within_quiet_hours(now.time(), start_t, end_t):
        return None
    return _alert(
        "OFF_HOURS_JOIN", SEV_QUIET,
        f"Off-hours join: {device['mac']}",
        detail=f"{device['mac']} joined at {now.strftime('%H:%M')} "
               f"(quiet hours {start_hhmm}-{end_hhmm}).",
        device_id=device.get("id"))


# --- IP churn ----------------------------------------------------------------
def rule_ip_churn(device: dict, distinct_ip_count: int, threshold: int,
                  window_minutes: int) -> dict | None:
    """One MAC used `distinct_ip_count` IPs within the window. Fires at/over the
    threshold. None below it."""
    if distinct_ip_count < threshold:
        return None
    return _alert(
        "IP_CHURN", SEV_IP_CHURN,
        f"Rapid IP changes for {device['mac']}",
        detail=f"{device['mac']} used {distinct_ip_count} distinct IPs in "
               f"{window_minutes} min (threshold {threshold}).",
        device_id=device.get("id"))


# --- service anomaly ---------------------------------------------------------
def rule_service_anomaly(device: dict, open_ports: list[int],
                         watch_ports: set[int]) -> dict | None:
    """A device exposes ports on the watch-list (sensitive/admin services that
    are unusual for an ordinary client). None if it exposes none of them."""
    hits = sorted(set(open_ports) & set(watch_ports))
    if not hits:
        return None
    return _alert(
        "SERVICE_ANOMALY", SEV_SERVICE,
        f"Unexpected service ports on {device['mac']}",
        detail=f"{device['mac']} ({device.get('last_ip') or '?'}) exposes "
               f"watched ports: {', '.join(str(p) for p in hits)}.",
        device_id=device.get("id"))
