"""
data/repos.py
=============
Repository functions — the ONLY place that contains SQL (all parameterized).

CORRECTNESS GUARANTEES (see persist_scan + reconcile_offline):
  * A device that leaves and returns keeps ONE row in `devices` (upsert by MAC).
  * A DHCP IP change updates last_ip; it never creates a second device row.
  * access_logs transitions are exact: 'joined' fires ONLY on the scan where a
    device reappears after being offline (or brand-new); 'present' on every
    subsequent scan it's seen; 'left' EXACTLY ONCE, after it has been missed for
    `offline_after_missed` consecutive scans.

No Flask imports here.
"""
from __future__ import annotations

import ipaddress
import logging
import re

from data import db

log = logging.getLogger(__name__)

_TIME_RE = re.compile(r"([01]\d|2[0-3]):[0-5]\d")

# ---------------------------------------------------------------------------
# Setting metadata + constraints (Module 9.2 Threshold Management).
# This is the SINGLE SOURCE OF TRUTH for what a valid setting looks like. Both
# validate_setting() (server-side guard) and the settings form (labels/widgets)
# read it, so an admin can never store a value that would disable detection —
# e.g. a negative interval, a non-numeric threshold, or a bad CIDR. Keys not
# listed here (internal keys such as gateway_mac_baseline) are stored as-is.
#   kind: int | time | cidr | text ; min/max bound the numeric thresholds.
# ---------------------------------------------------------------------------
SETTING_SPECS: dict[str, dict] = {
    # --- Scanning ---------------------------------------------------------
    "scan_interval_seconds": {
        "group": "scanning", "kind": "int", "min": 5, "max": 3600, "unit": "seconds",
        "label": "How often to scan the network",
        "help": "Time between automatic network scans. Lower finds new devices "
                "faster but creates more network traffic. Recommended: 30–60 seconds."},
    "profile_interval_seconds": {
        "group": "scanning", "kind": "int", "min": 30, "max": 86400, "unit": "seconds",
        "label": "How often to identify devices",
        "help": "Time between deeper checks that look up each device's open ports "
                "and operating system. These are slow, so keep this much longer "
                "than the scan interval."},
    "offline_after_missed": {
        "group": "scanning", "kind": "int", "min": 1, "max": 100, "unit": "missed scans",
        "label": "Mark a device as gone after",
        "help": "How many scans in a row a device can be missing before it is "
                "marked as having left. Raise this if phones that fall asleep keep "
                "showing false 'left' events."},

    # --- Threat detection ---------------------------------------------------
    "portscan_port_threshold": {
        "group": "detection", "kind": "int", "min": 2, "max": 1000, "unit": "ports",
        "label": "Port-scan alert: ports probed",
        "help": "Raise a Port Scan alert when one device tries this many different "
                "ports within the time window below. Lower is more sensitive but "
                "gives more false alarms."},
    "portscan_window_seconds": {
        "group": "detection", "kind": "int", "min": 5, "max": 3600, "unit": "seconds",
        "label": "Port-scan alert: time window",
        "help": "The period over which ports are counted for the port-scan alert."},
    "arp_conflict_window_seconds": {
        "group": "detection", "kind": "int", "min": 5, "max": 3600, "unit": "seconds",
        "label": "Spoofing alert: time window",
        "help": "If two different devices claim the same IP address within this "
                "time, raise an ARP Spoofing alert — a common sign that someone is "
                "trying to intercept network traffic."},
    "ipchurn_distinct_ips": {
        "group": "detection", "kind": "int", "min": 2, "max": 100, "unit": "IP addresses",
        "label": "IP-hopping alert: addresses used",
        "help": "Raise an alert when one device uses this many different IP "
                "addresses within the time window below. Normal devices rarely "
                "change IP this often."},
    "ipchurn_window_minutes": {
        "group": "detection", "kind": "int", "min": 1, "max": 1440, "unit": "minutes",
        "label": "IP-hopping alert: time window",
        "help": "The period over which a device's IP addresses are counted."},
    "service_watch_ports": {
        "group": "detection", "kind": "text", "unit": "",
        "label": "Risky ports to watch",
        "help": "Port numbers separated by commas. If a device has any of these "
                "open, a Risky Service alert is raised. Examples: 22 = SSH, "
                "23 = Telnet, 445 = file sharing, 3389 = Remote Desktop."},

    # --- Alerts ---------------------------------------------------------------
    "alert_dedup_seconds": {
        "group": "alerts", "kind": "int", "min": 30, "max": 86400, "unit": "seconds",
        "label": "Don't repeat the same alert for",
        "help": "If the same problem happens again for the same device within this "
                "time, no duplicate alert is created. Prevents alert flooding."},
    "unauth_return_rate_limit_seconds": {
        "group": "alerts", "kind": "int", "min": 60, "max": 86400, "unit": "seconds",
        "label": "Re-alert for returning unauthorized devices every",
        "help": "When an unauthorized device reconnects, alert at most once in this "
                "period. 3600 seconds = once per hour."},

    # --- Quiet hours ------------------------------------------------------------
    "quiet_hours_start": {
        "group": "quiet", "kind": "time", "unit": "",
        "label": "Quiet hours begin",
        "help": "Devices that join the network during quiet hours (for example "
                "overnight) raise an Off-hours alert."},
    "quiet_hours_end": {
        "group": "quiet", "kind": "time", "unit": "",
        "label": "Quiet hours end",
        "help": "When quiet hours stop. The period may cross midnight "
                "(for example 22:00 to 06:00)."},

    # --- Data & network ---------------------------------------------------------
    "log_retention_days": {
        "group": "data", "kind": "int", "min": 1, "max": 3650, "unit": "days",
        "label": "Keep history for",
        "help": "Presence history and scan records older than this are deleted "
                "automatically every night to save space. Alerts are kept."},
    "monitor_interface": {
        "group": "data", "kind": "text", "unit": "",
        "label": "Network adapter being monitored",
        "help": "Filled in automatically when you choose an adapter under "
                "'Monitored interface' above."},
    "monitor_subnet": {
        "group": "data", "kind": "cidr", "unit": "",
        "label": "Address range scanned",
        "help": "The block of IP addresses to scan, e.g. 192.168.1.0/24 covers "
                "192.168.1.1–192.168.1.254. Filled in automatically from the adapter."},
}

# Display order + plain-English intro for each settings section.
SETTING_GROUPS: list[dict] = [
    {"key": "scanning",  "title": "Scanning",
     "intro": "How often PWNM checks the network and decides a device has left."},
    {"key": "detection", "title": "Threat detection",
     "intro": "When suspicious behaviour becomes an alert. Lower numbers = more sensitive."},
    {"key": "alerts",    "title": "Alerts",
     "intro": "How often repeated alerts are shown, to avoid flooding."},
    {"key": "quiet",     "title": "Quiet hours",
     "intro": "A time window when new devices joining is treated as suspicious."},
    {"key": "data",      "title": "Data & network",
     "intro": "How long history is kept and which network is monitored."},
]

# Friendly names for keys that are not user-editable but appear in the audit trail.
SETTING_LABELS_EXTRA = {"gateway_mac_baseline": "Gateway ARP baseline"}


def setting_label(key: str) -> str:
    """Human-readable name for a setting key (falls back to the key itself)."""
    spec = SETTING_SPECS.get(key)
    return spec["label"] if spec else SETTING_LABELS_EXTRA.get(key, key)


def validate_setting(key: str, value) -> tuple[bool, object]:
    """Validate/coerce a setting value against SETTING_SPECS (Module 9.6).

    Returns (True, coerced_value) or (False, error_message). Enforces type and
    range so an invalid threshold cannot silently disable detection. Unknown
    keys (internal, not admin-editable) pass through unchanged.
    """
    spec = SETTING_SPECS.get(key)
    raw = "" if value is None else str(value).strip()
    if spec is None:
        return True, raw                       # internal key — store verbatim
    kind = spec["kind"]
    label = spec.get("label", key)
    unit = f" {spec['unit']}" if spec.get("unit") else ""

    if kind == "int":
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return False, f"{label}: please enter a whole number."
        lo, hi = spec.get("min"), spec.get("max")
        if lo is not None and n < lo:
            return False, f"{label}: must be at least {lo}{unit}."
        if hi is not None and n > hi:
            return False, f"{label}: must be at most {hi}{unit}."
        return True, n
    if kind == "time":
        if not _TIME_RE.fullmatch(raw):
            return False, f"{label}: enter a time like 22:30 (24-hour clock)."
        return True, raw
    if kind == "cidr":
        try:
            ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return False, f"{label}: enter an address range like 192.168.1.0/24."
        return True, raw
    # text
    if not raw:
        return False, f"{label}: cannot be empty."
    if len(raw) > 255:
        return False, f"{label}: too long (max 255 characters)."
    return True, raw


# ===========================================================================
# settings — with type coercion
# ===========================================================================
def _coerce(value: str):
    """Coerce a stored string to int / float / bool where it clearly is one,
    otherwise return the string unchanged (e.g. '60'->60, '00:00'->'00:00')."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    low = value.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    return value


def get_setting(key: str, default=None):
    """Return the setting value, type-coerced. Missing key -> default."""
    row = db.query_one(
        "SELECT setting_value FROM settings WHERE setting_key = %s", (key,))
    return _coerce(row["setting_value"]) if row else default


def get_int_setting(key: str, default: int = 0) -> int:
    val = get_setting(key, default)
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def set_setting(key: str, value) -> None:
    """Validate then persist a setting. Raises ValueError if the value violates
    its constraint, so bad input can never reach the settings table (defence in
    depth behind the route-level check)."""
    ok, result = validate_setting(key, value)
    if not ok:
        raise ValueError(result)
    db.execute(
        "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
        (key, str(result)))


def get_all_settings() -> dict:
    return {r["setting_key"]: _coerce(r["setting_value"])
            for r in db.query("SELECT setting_key, setting_value FROM settings")}


def list_settings() -> list[dict]:
    """All settings with their descriptions for the admin page (Module 9.3).
    Keeps the DB's own description text as the single source of truth."""
    return db.query(
        "SELECT setting_key, setting_value, description FROM settings "
        "ORDER BY setting_key")


# ===========================================================================
# users  (auth is Phase 4; hashing happens in the web layer, not here)
# ===========================================================================
def get_user_by_id(user_id: int) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE id = %s", (user_id,))


def get_user_by_username(username: str) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE username = %s", (username,))


def create_user(username: str, password_hash: str, full_name: str | None,
                role: str, is_active: bool = True) -> int:
    """Insert a user. `password_hash` must already be a werkzeug hash — this
    layer never sees or stores a plaintext password."""
    return db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, is_active) "
        "VALUES (%s, %s, %s, %s, %s)",
        (username, password_hash, full_name, role, 1 if is_active else 0))


def list_users() -> list[dict]:
    return db.query(
        "SELECT id, username, full_name, role, is_active, created_at "
        "FROM users ORDER BY username")


def set_user_active(user_id: int, is_active: bool) -> None:
    db.execute("UPDATE users SET is_active = %s WHERE id = %s",
               (1 if is_active else 0, user_id))


def deactivate_user(user_id: int) -> None:
    """Disable an account (Module 1.1) — is_active=0, preserving the user's audit
    history rather than deleting the row."""
    set_user_active(user_id, False)


def update_user_password(user_id: int, password_hash: str) -> None:
    db.execute("UPDATE users SET password_hash = %s WHERE id = %s",
               (password_hash, user_id))


def set_user_role(user_id: int, role: str) -> None:
    db.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))


def count_active_admins() -> int:
    """Number of enabled admin accounts — used to refuse the last-admin
    demote/disable that would lock everyone out of the admin area."""
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = 1")
    return int(row["c"]) if row else 0


# ===========================================================================
# devices
# ===========================================================================
def _clean(value: str | None) -> str | None:
    """Turn empty/'unknown' scan values into NULL so upsert's COALESCE keeps any
    previously-known value. Note 'Randomized (private MAC)' is intentionally
    kept (it is meaningful, not unknown)."""
    if not value:
        return None
    s = value.strip()
    if not s or s.lower() == "unknown":
        return None
    return s


def get_device_by_mac(mac: str) -> dict | None:
    return db.query_one("SELECT * FROM devices WHERE mac_address = %s", (mac,))


def get_device_by_ip(ip: str) -> dict | None:
    """Most-recently-seen device currently holding `ip` (IP is not unique, so we
    take the freshest). Used by the detection engine to map a scanner/sniffer IP
    back to a device row."""
    return db.query_one(
        "SELECT * FROM devices WHERE last_ip = %s ORDER BY last_seen DESC LIMIT 1",
        (ip,))


def get_device(device_id: int) -> dict | None:
    return db.query_one("SELECT * FROM devices WHERE id = %s", (device_id,))


def list_devices(status: str | None = None) -> list[dict]:
    if status:
        return db.query(
            "SELECT * FROM devices WHERE status = %s ORDER BY last_seen DESC",
            (status,))
    return db.query("SELECT * FROM devices ORDER BY last_seen DESC")


def get_online_devices() -> list[dict]:
    return db.query("SELECT * FROM devices WHERE is_online = 1 ORDER BY last_ip")


def count_devices() -> dict:
    """Dashboard counts (online / unauthorized / blocked / total)."""
    row = db.query_one(
        "SELECT "
        " COUNT(*) AS total, "
        " SUM(is_online = 1) AS online, "
        " SUM(status = 'unauthorized') AS unauthorized, "
        " SUM(status = 'blocked') AS blocked "
        "FROM devices")
    # SUM(...) returns Decimal/None — normalise to plain ints.
    return {k: int(v or 0) for k, v in row.items()}


def upsert_device(mac: str, ip: str | None, hostname: str | None,
                  vendor: str | None) -> tuple[int, bool]:
    """Insert a new device or update an existing one, keyed by MAC.

    Returns (device_id, is_new). On UPDATE we touch only observable attributes
    (last_ip, hostname, vendor, last_seen, is_online=1) and DELIBERATELY leave
    `status`, `device_label`, `first_seen` and the authorization columns alone,
    so an admin's decisions are never overwritten by a routine scan.

    `id = LAST_INSERT_ID(id)` makes lastrowid return the row id on BOTH insert
    and update, so we get device_id in one statement.
    """
    is_new = get_device_by_mac(mac) is None
    device_id = db.execute(
        """
        INSERT INTO devices
            (mac_address, last_ip, hostname, vendor,
             is_online, first_seen, last_seen, status)
        VALUES (%s, %s, %s, %s, 1, NOW(), NOW(), 'unauthorized')
        ON DUPLICATE KEY UPDATE
            last_ip   = VALUES(last_ip),
            hostname  = COALESCE(VALUES(hostname), hostname),
            vendor    = COALESCE(VALUES(vendor),   vendor),
            is_online = 1,
            last_seen = NOW(),
            id        = LAST_INSERT_ID(id)
        """,
        (mac, ip, _clean(hostname), _clean(vendor)))
    return device_id, is_new


def mark_device_offline(device_id: int) -> None:
    db.execute("UPDATE devices SET is_online = 0 WHERE id = %s", (device_id,))


def devices_needing_profile(limit: int = 3) -> list[dict]:
    """Online devices that nmap hasn't profiled yet (no OS estimate). Bounds the
    slow profiler to a few hosts per pass (Module 2.4)."""
    return db.query(
        "SELECT * FROM devices WHERE is_online = 1 "
        "AND (os_guess IS NULL OR os_guess = '') "
        "ORDER BY last_seen DESC LIMIT %s",
        (int(limit),))


def set_device_profile(device_id: int, os_guess: str | None,
                       open_ports: list | None) -> None:
    """Store an nmap profile. os_guess is set to a non-empty sentinel even when
    unknown, so a device isn't re-profiled every pass; open_ports is CSV."""
    ports_csv = ",".join(str(p) for p in open_ports) if open_ports else None
    db.execute(
        "UPDATE devices SET os_guess = %s, open_ports = %s WHERE id = %s",
        (os_guess or "unknown", ports_csv, device_id))


def set_device_status(device_id: int, status: str,
                      authorized_by: int | None = None) -> None:
    """Admin action (Phase 4/6): records who authorized/blocked and when."""
    db.execute(
        "UPDATE devices SET status = %s, authorized_by = %s, authorized_at = NOW() "
        "WHERE id = %s",
        (status, authorized_by, device_id))


# ===========================================================================
# scan sessions
# ===========================================================================
def start_scan_session(subnet: str | None, iface: str | None,
                       triggered_by: str = "scheduler",
                       user_id: int | None = None) -> int:
    return db.execute(
        "INSERT INTO scan_sessions (subnet, interface, triggered_by, user_id) "
        "VALUES (%s, %s, %s, %s)",
        (subnet, iface, triggered_by, user_id))


def finish_scan_session(scan_id: int, devices_found: int) -> None:
    db.execute(
        "UPDATE scan_sessions SET finished_at = NOW(), devices_found = %s "
        "WHERE id = %s",
        (devices_found, scan_id))


# ===========================================================================
# access logs
# ===========================================================================
def determine_event(seen_now: bool, was_online: bool) -> str:
    """Classify a device's presence transition (Module 4.1).

    Pure function so it is trivially testable:
      * seen this scan & was OFFLINE/new  -> 'joined'  (reappearance)
      * seen this scan & was already up    -> 'present'
      * not seen this scan                 -> 'left'    (the CALLER applies the
        offline_after_missed threshold before actually recording a 'left').
    """
    if seen_now:
        return "present" if was_online else "joined"
    return "left"


def log_access(device_id: int, scan_id: int | None,
               ip: str | None, event: str) -> None:
    db.execute(
        "INSERT INTO access_logs (device_id, scan_id, ip_address, event) "
        "VALUES (%s, %s, %s, %s)",
        (device_id, scan_id, ip, event))


def get_activity_feed(limit: int = 50, date_from=None, date_to=None) -> list[dict]:
    """Most-recent access events across all devices (Module 4.4) — the dashboard
    activity feed and the reports access-history export both read this. Optional
    date range for the report (fully parameterized)."""
    sql = ("SELECT al.*, d.mac_address, d.device_label "
           "FROM access_logs al JOIN devices d ON d.id = al.device_id")
    params: list = []
    where = []
    if date_from:
        where.append("al.seen_at >= %s")
        params.append(date_from)
    if date_to:
        where.append("al.seen_at <= %s")
        params.append(date_to)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY al.seen_at DESC, al.id DESC LIMIT %s"
    params.append(int(limit))
    return db.query(sql, tuple(params))


def get_device_history(device_id: int, date_from=None, date_to=None,
                       limit: int = 100, offset: int = 0) -> list[dict]:
    """Chronological access trail for one device (Module 4.4), optionally bounded
    by a date range (for reports) and paginated (for the detail page). All
    filters are parameterized — no string-built SQL."""
    sql = "SELECT * FROM access_logs WHERE device_id = %s"
    params: list = [device_id]
    if date_from:
        sql += " AND seen_at >= %s"
        params.append(date_from)
    if date_to:
        sql += " AND seen_at <= %s"
        params.append(date_to)
    sql += " ORDER BY seen_at DESC, id DESC LIMIT %s OFFSET %s"
    params += [int(limit), int(offset)]
    return db.query(sql, tuple(params))


def get_ip_history(device_id: int) -> list[dict]:
    """Distinct IP addresses a device has held over time (Module 4.4). Feeds the
    IP_CHURN detection rule and the device profile. Returns {ip, first_seen,
    last_seen, hits}, most-recently-used first."""
    return db.query(
        "SELECT ip_address AS ip, MIN(seen_at) AS first_seen, "
        "       MAX(seen_at) AS last_seen, COUNT(*) AS hits "
        "FROM access_logs WHERE device_id = %s AND ip_address IS NOT NULL "
        "GROUP BY ip_address ORDER BY last_seen DESC",
        (device_id,))


def distinct_ip_count(device_id: int, since_minutes: int) -> int:
    """How many distinct IPs a device has used in the last `since_minutes`
    (feeds the IP_CHURN rule)."""
    row = db.query_one(
        "SELECT COUNT(DISTINCT ip_address) AS c FROM access_logs "
        "WHERE device_id = %s AND ip_address IS NOT NULL "
        "AND seen_at >= (NOW() - INTERVAL %s MINUTE)",
        (device_id, int(since_minutes)))
    return int(row["c"]) if row else 0


def count_access_history(device_id: int) -> int:
    """Total access-log rows for a device (for pagination)."""
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM access_logs WHERE device_id = %s", (device_id,))
    return int(row["c"]) if row else 0


# ===========================================================================
# offline reconciliation  ('left' detection)
# ===========================================================================
def reconcile_offline(scan_id: int, missed_threshold: int) -> list[str]:
    """Mark devices missed for >= `missed_threshold` consecutive scans offline.

    A device's "consecutive misses" = the number of scan_sessions that started
    AFTER its last_seen. A device seen this scan has last_seen = NOW(), so its
    miss count is 0; an absent device's count grows by one each scan. We only
    consider is_online = 1 devices, so once a device is flipped offline here it
    is not reconsidered — guaranteeing exactly ONE 'left' row per departure.

    Returns the MACs that transitioned to offline this scan.
    """
    candidates = db.query(
        "SELECT d.id, d.mac_address, d.last_ip, "
        "  (SELECT COUNT(*) FROM scan_sessions s WHERE s.started_at > d.last_seen) "
        "  AS misses "
        "FROM devices d WHERE d.is_online = 1")

    left: list[str] = []
    for c in candidates:
        if c["misses"] >= missed_threshold:
            mark_device_offline(c["id"])
            log_access(c["id"], scan_id, c["last_ip"], "left")
            left.append(c["mac_address"])
    return left


# ===========================================================================
# alerts  (thin API now; the detection engine in Phase 6 builds on this)
# ===========================================================================
def insert_alert(rule_code: str, severity: str, title: str,
                 detail: str | None = None, device_id: int | None = None) -> int:
    return db.execute(
        "INSERT INTO alerts (device_id, rule_code, severity, title, detail) "
        "VALUES (%s, %s, %s, %s, %s)",
        (device_id, rule_code, severity, title, detail))


def _alert_filter_sql(severity, status, date_from, date_to):
    """Shared parameterized WHERE for get_alerts/count_alerts."""
    sql, params = " WHERE 1 = 1", []
    if severity:
        sql += " AND a.severity = %s"
        params.append(severity)
    if status:
        sql += " AND a.status = %s"
        params.append(status)
    if date_from:
        sql += " AND a.created_at >= %s"
        params.append(date_from)
    if date_to:
        sql += " AND a.created_at <= %s"
        params.append(date_to)
    return sql, params


def get_alerts(severity: str | None = None, status: str | None = None,
               date_from=None, date_to=None, limit: int = 100,
               offset: int = 0) -> list[dict]:
    """Filtered, paginated alert list (Module 6.2). All filters are optional and
    fully parameterized."""
    where, params = _alert_filter_sql(severity, status, date_from, date_to)
    return db.query(
        "SELECT a.*, d.mac_address, d.device_label FROM alerts a "
        "LEFT JOIN devices d ON d.id = a.device_id" + where +
        " ORDER BY a.created_at DESC, a.id DESC LIMIT %s OFFSET %s",
        tuple(params + [int(limit), int(offset)]))


def count_alerts(severity: str | None = None, status: str | None = None,
                 date_from=None, date_to=None) -> int:
    """Total alerts matching the filters (for pagination)."""
    where, params = _alert_filter_sql(severity, status, date_from, date_to)
    row = db.query_one("SELECT COUNT(*) AS c FROM alerts a" + where, tuple(params))
    return int(row["c"]) if row else 0


def get_alert(alert_id: int) -> dict | None:
    return db.query_one(
        "SELECT a.*, d.mac_address, d.device_label FROM alerts a "
        "LEFT JOIN devices d ON d.id = a.device_id WHERE a.id = %s", (alert_id,))


def get_alert_detail(alert_id: int) -> dict | None:
    """Module 6 — the alert with its triggering EVIDENCE and the device record.
    Returns {alert, device, history, ip_history} or None if the alert is gone."""
    alert = get_alert(alert_id)
    if not alert:
        return None
    device = get_device(alert["device_id"]) if alert.get("device_id") else None
    history, ip_history = [], []
    if device:
        history = get_device_history(device["id"], limit=15)
        ip_history = get_ip_history(device["id"])
    return {"alert": alert, "device": device,
            "history": history, "ip_history": ip_history}


def recent_alert_exists(rule_code: str, device_id: int | None,
                        within_seconds: int) -> bool:
    """True if an alert with this (rule_code, device_id) was created within the
    lookback window — the de-duplication / rate-limit primitive."""
    if device_id is None:
        row = db.query_one(
            "SELECT 1 AS x FROM alerts WHERE rule_code = %s AND device_id IS NULL "
            "AND created_at >= (NOW() - INTERVAL %s SECOND) LIMIT 1",
            (rule_code, int(within_seconds)))
    else:
        row = db.query_one(
            "SELECT 1 AS x FROM alerts WHERE rule_code = %s AND device_id = %s "
            "AND created_at >= (NOW() - INTERVAL %s SECOND) LIMIT 1",
            (rule_code, device_id, int(within_seconds)))
    return row is not None


def acknowledge_alert(alert_id: int, user_id: int) -> None:
    db.execute(
        "UPDATE alerts SET status = 'acknowledged', ack_by = %s, ack_at = NOW() "
        "WHERE id = %s AND status = 'new'", (user_id, alert_id))


def resolve_alert(alert_id: int, user_id: int, note: str | None = None) -> None:
    """Close an alert, recording who resolved it and an optional reason note
    (Module 6.3 accountability)."""
    db.execute(
        "UPDATE alerts SET status = 'resolved', ack_by = %s, ack_at = NOW(), "
        "resolution_note = %s WHERE id = %s",
        (user_id, note or None, alert_id))


# Severity weighting for the nav badge (higher = more urgent).
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8}


def get_unread_count() -> dict:
    """Severity-weighted summary of NEW alerts for the nav badge (Module 6.2).
    Returns {count, weight, top_severity} — the badge shows count, coloured by
    the highest-severity unread alert."""
    rows = db.query(
        "SELECT severity, COUNT(*) AS c FROM alerts WHERE status = 'new' "
        "GROUP BY severity")
    counts = {r["severity"]: int(r["c"]) for r in rows}
    total = sum(counts.values())
    weight = sum(_SEVERITY_WEIGHT.get(s, 1) * c for s, c in counts.items())
    top = next((s for s in ("critical", "high", "medium", "low") if counts.get(s)),
               None)
    return {"count": total, "weight": weight, "top_severity": top}


def count_open_alerts() -> int:
    row = db.query_one("SELECT COUNT(*) AS c FROM alerts WHERE status = 'new'")
    return int(row["c"]) if row else 0


def alerts_by_severity() -> dict:
    rows = db.query(
        "SELECT severity, COUNT(*) AS c FROM alerts "
        "WHERE status != 'resolved' GROUP BY severity")
    return {r["severity"]: int(r["c"]) for r in rows}


# ===========================================================================
# ORCHESTRATION — persist one scan round (uses the discrete functions above)
# ===========================================================================
def persist_scan(devices: list[dict], subnet: str | None, iface: str | None,
                 triggered_by: str = "scheduler", user_id: int | None = None,
                 missed_threshold: int | None = None) -> dict:
    """Persist one scan's devices and compute joined/present/left transitions.

    Steps (this is the exact sequence a panelist may ask you to walk through):
      1. open a scan_session;
      2. snapshot which MACs were online BEFORE this scan (to tell joined vs
         present — captured before any upsert changes is_online);
      3. upsert each seen device and log 'joined' (was offline/new) or 'present';
      4. reconcile_offline() flips long-absent devices offline and logs 'left';
      5. close the scan_session.

    Returns {scan_id, devices_found, joined, present, left, new_devices}.
    """
    if missed_threshold is None:
        missed_threshold = get_int_setting("offline_after_missed", 3)

    scan_id = start_scan_session(subnet, iface, triggered_by, user_id)

    prior_online = {r["mac_address"] for r in
                    db.query("SELECT mac_address FROM devices WHERE is_online = 1")}

    joined, present, new_devices = [], [], []
    for d in devices:
        mac = d["mac"]
        device_id, is_new = upsert_device(
            mac, d.get("ip"), d.get("hostname"), d.get("vendor"))
        if is_new:
            new_devices.append(mac)
        # Classify the transition (Module 4.1) from the pre-scan online snapshot.
        event = determine_event(seen_now=True, was_online=(mac in prior_online))
        (present if event == "present" else joined).append(mac)
        log_access(device_id, scan_id, d.get("ip"), event)

    left = reconcile_offline(scan_id, missed_threshold)
    finish_scan_session(scan_id, len(devices))

    summary = {
        "scan_id": scan_id,
        "devices_found": len(devices),
        "joined": joined,
        "present": present,
        "left": left,
        "new_devices": new_devices,
    }
    log.info("scan #%d persisted: found=%d joined=%d present=%d left=%d new=%d",
             scan_id, len(devices), len(joined), len(present), len(left),
             len(new_devices))
    return summary


# ===========================================================================
# Phase 5 — dashboard / devices view helpers
# ===========================================================================
def query_devices(status: str | None = None, online: bool | None = None,
                  limit: int | None = None, offset: int = 0) -> list[dict]:
    """Filtered device list for the /devices table. The optional filters are
    applied with `(%s IS NULL OR col = %s)` so the query stays fully
    parameterized (no string concatenation of user input). Pass limit/offset for
    pagination."""
    online_val = None if online is None else (1 if online else 0)
    sql = ("SELECT * FROM devices "
           "WHERE (%s IS NULL OR status = %s) "
           "  AND (%s IS NULL OR is_online = %s) "
           "ORDER BY is_online DESC, last_seen DESC")
    params: list = [status, status, online_val, online_val]
    if limit is not None:
        sql += " LIMIT %s OFFSET %s"
        params += [int(limit), int(offset)]
    return db.query(sql, tuple(params))


def count_devices_filtered(status: str | None = None,
                           online: bool | None = None) -> int:
    """Total rows matching the /devices filters (for pagination)."""
    online_val = None if online is None else (1 if online else 0)
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM devices "
        "WHERE (%s IS NULL OR status = %s) "
        "  AND (%s IS NULL OR is_online = %s)",
        (status, status, online_val, online_val))
    return int(row["c"]) if row else 0


def set_device_label(device_id: int, label: str | None) -> None:
    db.execute("UPDATE devices SET device_label = %s WHERE id = %s",
               (label or None, device_id))


def authorize_device(device_id: int, admin_id: int) -> None:
    set_device_status(device_id, "authorized", admin_id)
    db.execute("UPDATE devices SET block_reason = NULL WHERE id = %s", (device_id,))


# User-facing wording for device statuses. The stored value stays 'blocked'
# (DB enum, rule BLOCKED_SEEN, existing alerts), but the UI calls it "flagged":
# PWNM is passive — it never cuts a device off, it flags it for the admin.
STATUS_LABELS = {"authorized": "authorized", "unauthorized": "unauthorized",
                 "blocked": "flagged"}


# ---------------------------------------------------------------------------
# Plain-English names for detection rules. The stored rule_code never changes
# (it is the engine's identifier and lives in every existing alert row); these
# are display-only, used by the alerts pages, the "by rule" chart and reports.
# ---------------------------------------------------------------------------
RULE_LABELS: dict[str, str] = {
    "UNAUTH_NEW":       "New unknown device",
    "UNAUTH_RETURN":    "Unauthorized device returned",
    "BLOCKED_SEEN":     "Flagged device seen",
    "ARP_SPOOF":        "Gateway impersonation",
    "ARP_CONFLICT":     "Two devices, one IP address",
    "PORT_SCAN":        "Port scanning",
    "OFF_HOURS_JOIN":   "Joined during quiet hours",
    "IP_CHURN":         "Rapidly changing IP address",
    "SERVICE_ANOMALY":  "Risky service exposed",
}

# One sentence explaining what the rule means and why it matters, shown on the
# alert detail page so an operator does not need the thesis to interpret it.
RULE_EXPLAIN: dict[str, str] = {
    "UNAUTH_NEW":
        "A device that has never been seen before joined the network. Check "
        "whether you recognise it, then mark it Authorized or Flag it.",
    "UNAUTH_RETURN":
        "A device you have not authorized connected again. It has been seen "
        "before but was never approved.",
    "BLOCKED_SEEN":
        "A device you flagged is back on the network. PWNM cannot disconnect "
        "it — block its MAC address on the router.",
    "ARP_SPOOF":
        "The router's hardware (MAC) address changed unexpectedly. Someone may "
        "be pretending to be the router to intercept traffic.",
    "ARP_CONFLICT":
        "Two devices claimed the same IP address. This is usually a sign of "
        "ARP poisoning, sometimes a misconfigured device.",
    "PORT_SCAN":
        "One device probed many different ports in a short time — typically "
        "someone mapping the network for weaknesses.",
    "OFF_HOURS_JOIN":
        "A device joined during your configured quiet hours, when the network "
        "is normally idle.",
    "IP_CHURN":
        "One device used several different IP addresses very quickly, which "
        "can indicate spoofing or a misbehaving device.",
    "SERVICE_ANOMALY":
        "A device has a sensitive port open (such as remote access or file "
        "sharing), which widens the attack surface.",
}


def rule_label(rule_code: str) -> str:
    """Plain-English name for a detection rule (falls back to the code)."""
    return RULE_LABELS.get(rule_code or "", rule_code or "")


def rule_explain(rule_code: str) -> str:
    """One-sentence explanation of what a rule means (may be empty)."""
    return RULE_EXPLAIN.get(rule_code or "", "")

def status_label(status: str | None) -> str:
    """Display label for a device status ('blocked' -> 'flagged')."""
    return STATUS_LABELS.get(status or "", status or "")


def block_device(device_id: int, admin_id: int, reason: str | None = None) -> None:
    """Mark a device blocked and record WHY (Module 3.4). 'blocked' is an
    authorization STATE only — the system never sends deauth/traffic blocks; it
    flags the device and emits the MAC-filter instruction for the router admin."""
    set_device_status(device_id, "blocked", admin_id)
    db.execute("UPDATE devices SET block_reason = %s WHERE id = %s",
               (reason or None, device_id))


def generate_mac_filter(device_id: int) -> str | None:
    """The router MAC-filter instruction text for a device (Module 3.4). The
    system does NOT enforce blocking; the admin applies this on the router."""
    device = get_device(device_id)
    if not device:
        return None
    return (f"Add a MAC-address filter / deny rule for {device['mac_address']} "
            f"on your router's admin page (Wireless MAC Filtering -> Deny). "
            f"PWNM does not cut traffic itself; it flags the device and raises a "
            f"critical alert on every reappearance.")


def get_device_alerts(device_id: int, limit: int = 20, offset: int = 0) -> list[dict]:
    """Alerts raised for a device, newest first (for the device detail page)."""
    return db.query(
        "SELECT * FROM alerts WHERE device_id = %s "
        "ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
        (device_id, int(limit), int(offset)))


def count_device_alerts(device_id: int) -> int:
    """Total alerts for a device (paginates the detail page's Related alerts)."""
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM alerts WHERE device_id = %s", (device_id,))
    return int(row["c"]) if row else 0


def merge_devices(primary_id: int, duplicate_id: int) -> bool:
    """Fold a duplicate device into the primary (Module 3.3) — the mitigation for
    MAC randomization creating apparent new devices.

    Reassigns the duplicate's access history and alerts to the primary, carries
    forward the most-recent sighting, then deletes the duplicate row. Returns
    False if the ids are the same or either device is missing.
    """
    if primary_id == duplicate_id:
        return False
    primary = get_device(primary_id)
    duplicate = get_device(duplicate_id)
    if not primary or not duplicate:
        return False

    # Move the duplicate's evidence onto the primary.
    db.execute("UPDATE access_logs SET device_id = %s WHERE device_id = %s",
               (primary_id, duplicate_id))
    db.execute("UPDATE alerts SET device_id = %s WHERE device_id = %s",
               (primary_id, duplicate_id))
    # Keep the earliest first_seen and the latest last_seen/last_ip (computed in
    # Python for clarity — the primary's admin decisions are otherwise untouched).
    first_seen = min(primary["first_seen"], duplicate["first_seen"])
    if duplicate["last_seen"] >= primary["last_seen"]:
        last_seen, last_ip = duplicate["last_seen"], duplicate["last_ip"] or primary["last_ip"]
    else:
        last_seen, last_ip = primary["last_seen"], primary["last_ip"]
    is_online = 1 if (primary["is_online"] or duplicate["is_online"]) else 0
    db.execute(
        "UPDATE devices SET first_seen = %s, last_seen = %s, last_ip = %s, "
        "is_online = %s WHERE id = %s",
        (first_seen, last_seen, last_ip, is_online, primary_id))
    db.execute("DELETE FROM devices WHERE id = %s", (duplicate_id,))
    return True


def get_device_detail(device_id: int) -> dict | None:
    """Full device profile + access history + related alerts + the MAC-filter
    instruction (Module 3). Returns None if the device is gone."""
    device = get_device(device_id)
    if not device:
        return None
    return {
        "device": device,
        "history": get_device_history(device_id, limit=100),
        "ip_history": get_ip_history(device_id),
        "alerts": get_device_alerts(device_id),
        "mac_filter": generate_mac_filter(device_id) if device["status"] == "blocked" else None,
    }


def last_finished_scan() -> dict | None:
    return db.query_one(
        "SELECT * FROM scan_sessions WHERE finished_at IS NOT NULL "
        "ORDER BY id DESC LIMIT 1")


def chart_devices_over_time(limit: int = 20) -> list[dict]:
    """Module 7.3 — devices_found per recent finished scan (oldest-first so the
    line reads left to right)."""
    rows = db.query(
        "SELECT id, finished_at, devices_found FROM scan_sessions "
        "WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT %s",
        (int(limit),))
    return list(reversed(rows))


def chart_alerts_by_severity() -> list[dict]:
    """Module 7.3 — unresolved alert counts per severity, ordered low->critical
    with a zero for empty buckets so the distribution chart has stable
    categories."""
    by = alerts_by_severity()          # {severity: count} for non-resolved alerts
    order = ("low", "medium", "high", "critical")
    return [{"severity": s, "count": int(by.get(s, 0))} for s in order]


def get_summary() -> dict:
    """Module 7.1 — the headline dashboard numbers: device counts, open-alert
    count, and the last finished scan."""
    return {
        "counts": count_devices(),        # {total, online, unauthorized, blocked}
        "open_alerts": count_open_alerts_broad(),
        "last_scan": last_finished_scan(),
    }


def prune_old_records(days: int) -> dict:
    """Delete access_logs and finished scan_sessions older than `days` (data
    retention — bounds unbounded history growth). Returns rows removed per table.
    access_logs are deleted first so no scan_sessions FK dangles."""
    days = max(1, int(days))
    logs = db.execute(
        "DELETE FROM access_logs WHERE seen_at < (NOW() - INTERVAL %s DAY)", (days,))
    scans = db.execute(
        "DELETE FROM scan_sessions WHERE finished_at IS NOT NULL "
        "AND finished_at < (NOW() - INTERVAL %s DAY)", (days,))
    return {"access_logs": int(logs), "scan_sessions": int(scans)}


def record_setting_change(setting_key: str, old_value, new_value,
                          changed_by: int | None) -> None:
    """Append a configuration-change audit record (Module 9 accountability)."""
    if str(old_value) == str(new_value):
        return                                       # no-op change, don't log noise
    db.execute(
        "INSERT INTO setting_audit (setting_key, old_value, new_value, changed_by) "
        "VALUES (%s, %s, %s, %s)",
        (setting_key,
         None if old_value is None else str(old_value),
         None if new_value is None else str(new_value), changed_by))


def recent_setting_changes(limit: int = 20) -> list[dict]:
    """Most-recent configuration changes with the editor's username."""
    return db.query(
        "SELECT a.setting_key, a.old_value, a.new_value, a.changed_at, "
        "       u.username AS changed_by FROM setting_audit a "
        "LEFT JOIN users u ON u.id = a.changed_by "
        "ORDER BY a.changed_at DESC, a.id DESC LIMIT %s", (int(limit),))


def count_open_alerts_broad() -> int:
    """Open alerts for the dashboard tile = new + acknowledged (not yet resolved)."""
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM alerts WHERE status IN ('new', 'acknowledged')")
    return int(row["c"]) if row else 0


# ===========================================================================
# chart aggregates (Module * — /api/charts/*). COUNT/GROUP BY done in SQL;
# gap-fill and zero-fill (presentation) done by the route.
# ===========================================================================
# --- chart date-range helpers ---------------------------------------------
# Every chart query accepts an optional [start, end) datetime window. With no
# window it keeps its original rolling default (last N hours/days), so callers
# that pass nothing behave exactly as before.
_BUCKET_FMT = {"hour": "%Y-%m-%d %H:00", "day": "%Y-%m-%d"}


def _time_window(column: str, start, end, rolling_sql: str, rolling_arg) -> tuple[str, list]:
    """SQL condition + params for a chart window: explicit [start, end) if given,
    else the rolling default (e.g. 'NOW() - INTERVAL %s DAY')."""
    if start is not None and end is not None:
        return f"{column} >= %s AND {column} < %s", [start, end]
    return f"{column} >= ({rolling_sql})", [int(rolling_arg)]


def chart_occupancy(hours: int = 24, start=None, end=None, bucket: str = "hour") -> list[dict]:
    """Distinct devices seen (joined/present) per hour or day (Chart 4.2 / 7.1).
    Window: [start, end) if given, else the last `hours`.
    Returns [{bucket 'YYYY-MM-DD HH:00' | 'YYYY-MM-DD', count}]."""
    fmt = _BUCKET_FMT.get(bucket, _BUCKET_FMT["hour"])
    cond, params = _time_window("seen_at", start, end, "NOW() - INTERVAL %s HOUR", hours)
    return db.query(
        f"SELECT DATE_FORMAT(seen_at, %s) AS bucket, "
        f"       COUNT(DISTINCT device_id) AS count "
        f"FROM access_logs "
        f"WHERE event IN ('joined', 'present') AND {cond} "
        f"GROUP BY bucket ORDER BY bucket",
        tuple([fmt] + params))


def chart_alerts_severity_counts(days: int = 7, open_only: bool = False,
                                 start=None, end=None) -> dict:
    """Alert counts per severity (Chart 6.1 / 7.2) within [start, end) if given,
    else the last `days`. open_only restricts to new+acknowledged.
    Returns {severity: count} (may omit zeros)."""
    cond, params = _time_window("created_at", start, end, "NOW() - INTERVAL %s DAY", days)
    sql = f"SELECT severity, COUNT(*) AS c FROM alerts WHERE {cond}"
    if open_only:
        sql += " AND status IN ('new', 'acknowledged')"
    sql += " GROUP BY severity"
    return {r["severity"]: int(r["c"]) for r in db.query(sql, tuple(params))}


def chart_alerts_over_time(days: int = 30, start=None, end=None) -> list[dict]:
    """Alert counts per day per severity (Chart 6.2) within [start, end) if given,
    else the last `days`. The route pivots these into one series per severity."""
    cond, params = _time_window("created_at", start, end, "NOW() - INTERVAL %s DAY", days)
    return db.query(
        f"SELECT DATE(created_at) AS d, severity, COUNT(*) AS c FROM alerts "
        f"WHERE {cond} GROUP BY d, severity ORDER BY d",
        tuple(params))


def chart_alerts_by_rule(days: int = 30, start=None, end=None) -> dict:
    """Alert counts per rule_code (Chart 6.3) within [start, end) if given, else
    the last `days`. {rule_code: count}; the route zero-fills and sorts."""
    cond, params = _time_window("created_at", start, end, "NOW() - INTERVAL %s DAY", days)
    return {r["rule_code"]: int(r["c"]) for r in db.query(
        f"SELECT rule_code, COUNT(*) AS c FROM alerts WHERE {cond} GROUP BY rule_code",
        tuple(params))}


def chart_device_status(start=None, end=None) -> dict:
    """Device counts per authorization status (Chart 3.1). {status: count}.
    With a window, only devices seen during [start, end) are counted."""
    # A device counts for a window if its known lifetime [first_seen, last_seen]
    # overlaps [start, end) — i.e. it was on the network at some point in it.
    if start is not None and end is not None:
        return {r["status"]: int(r["c"]) for r in db.query(
            "SELECT status, COUNT(*) AS c FROM devices "
            "WHERE first_seen < %s AND last_seen >= %s GROUP BY status", (end, start))}
    return {r["status"]: int(r["c"]) for r in db.query(
        "SELECT status, COUNT(*) AS c FROM devices GROUP BY status")}


def chart_vendor_counts(start=None, end=None) -> list[dict]:
    """All vendors by device count, descending (Chart 3.2). The route keeps the
    top N and folds the tail into 'Other'. NULL/empty vendors bucket as Unknown.
    With a window, only devices seen during [start, end) are counted."""
    # A device counts for a window if its known lifetime [first_seen, last_seen]
    # overlaps [start, end) — i.e. it was on the network at some point in it.
    where, params = "", ()
    if start is not None and end is not None:
        where, params = "WHERE first_seen < %s AND last_seen >= %s ", (end, start)
    return db.query(
        "SELECT COALESCE(NULLIF(vendor, ''), 'Unknown') AS vendor, "
        "COUNT(*) AS count FROM devices " + where +
        "GROUP BY COALESCE(NULLIF(vendor, ''), 'Unknown') ORDER BY count DESC", params)


def chart_scan_history(hours: int = 24, start=None, end=None, bucket: str = "hour") -> list[dict]:
    """Average devices_found per HOUR or DAY (Chart 2.1) within [start, end) if
    given, else the last `hours`.

    Scans run every ~60s, so plotting every scan is an unreadable wall of
    spikes. Bucketing gives a clean trend that still drops toward zero during a
    scanning outage (the fault the chart is meant to reveal)."""
    fmt = _BUCKET_FMT.get(bucket, _BUCKET_FMT["hour"])
    cond, params = _time_window("started_at", start, end, "NOW() - INTERVAL %s HOUR", hours)
    return db.query(
        f"SELECT DATE_FORMAT(started_at, %s) AS bucket, "
        f"       AVG(devices_found) AS avg_found, COUNT(*) AS scans "
        f"FROM scan_sessions "
        f"WHERE finished_at IS NOT NULL AND {cond} "
        f"GROUP BY bucket ORDER BY bucket",
        tuple([fmt] + params))


def chart_presence_events(day_start, day_end) -> list[dict]:
    """All access-log events within [day_start, day_end), with the device's
    name and current online flag, ordered per device chronologically (Chart 4.1).
    The route pairs joined->left events into floating [start, end] bars."""
    return db.query(
        "SELECT al.device_id, al.event, al.seen_at, al.ip_address, "
        "       d.device_label, d.hostname, d.mac_address, d.is_online "
        "FROM access_logs al JOIN devices d ON d.id = al.device_id "
        "WHERE al.seen_at >= %s AND al.seen_at < %s "
        "ORDER BY al.device_id, al.seen_at, al.id",
        (day_start, day_end))
