"""
Integration: the detection engine end-to-end (test DB), including alert
DE-DUPLICATION and the UNAUTH_RETURN rate limit, ARP spoof/conflict, IP churn,
and the service-anomaly rule.
"""
from datetime import datetime

from core.sniffer import SnifferState
from data import db, repos
from detection import engine


def _clear():
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")


def _seed_device(mac, status="unauthorized", ip="192.168.1.10"):
    did, _ = repos.upsert_device(mac, ip, "h", "Vendor")
    if status != "unauthorized":
        repos.set_device_status(did, status)
    return did


def _alerts(rule=None):
    if rule:
        return db.query("SELECT * FROM alerts WHERE rule_code = %s", (rule,))
    return db.query("SELECT * FROM alerts")


# --- storage API -------------------------------------------------------------
def test_insert_and_list_alert(seeded_db):
    _clear()
    aid = repos.insert_alert("UNAUTH_NEW", "high", "New device seen", "aa:bb")
    assert aid > 0 and any(a["id"] == aid for a in repos.get_alerts())


# --- engine generates alerts from a scan summary -----------------------------
def test_engine_creates_new_and_unauth_alerts(seeded_db):
    _clear()
    mac = "aa:00:00:00:00:10"
    _seed_device(mac, status="unauthorized")
    summary = {"scan_id": 1, "new_devices": [mac], "joined": [mac], "present": []}

    created = engine.evaluate(summary, now=datetime(2026, 6, 1, 12, 0, 0))
    codes = {a["rule_code"] for a in _alerts()}
    assert "UNAUTH_NEW" in codes
    assert "UNAUTH_RETURN" in codes
    assert len(created) == 2


def test_engine_creates_critical_for_blocked_seen(seeded_db):
    _clear()
    mac = "aa:00:00:00:00:11"
    _seed_device(mac, status="blocked")
    summary = {"scan_id": 1, "new_devices": [], "joined": [mac], "present": []}
    engine.evaluate(summary, now=datetime(2026, 6, 1, 12, 0, 0))
    blocked = _alerts("BLOCKED_SEEN")
    assert len(blocked) == 1 and blocked[0]["severity"] == "critical"


# --- de-duplication / rate limit --------------------------------------------
def test_alert_deduplication_within_window(seeded_db):
    _clear()
    mac = "aa:00:00:00:00:12"
    _seed_device(mac, status="unauthorized")
    summary = {"scan_id": 1, "new_devices": [], "joined": [mac], "present": []}

    engine.evaluate(summary, now=datetime(2026, 6, 1, 12, 0, 0))
    engine.evaluate(summary, now=datetime(2026, 6, 1, 12, 0, 30))   # 30s later

    assert len(_alerts("UNAUTH_RETURN")) == 1        # deduped


def test_unauth_return_rate_limit_is_independent_per_rule(seeded_db):
    _clear()
    did = _seed_device("aa:00:00:00:00:13", status="unauthorized")
    repos.insert_alert("UNAUTH_RETURN", "medium", "first", device_id=did)
    assert repos.recent_alert_exists("UNAUTH_RETURN", did, 3600) is True
    assert repos.recent_alert_exists("BLOCKED_SEEN", did, 3600) is False


# --- ARP spoof: gateway baseline + conflict ---------------------------------
def test_engine_arp_spoof_learns_then_alerts(seeded_db):
    _clear()
    summary = {"scan_id": 1, "new_devices": [], "joined": [], "present": []}
    engine.evaluate(summary, gateway={"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"})
    assert _alerts("ARP_SPOOF") == []
    assert repos.get_setting("gateway_mac_baseline") == "aa:aa:aa:aa:aa:aa"

    engine.evaluate(summary, gateway={"ip": "192.168.1.1", "mac": "bb:bb:bb:bb:bb:bb"})
    assert len(_alerts("ARP_SPOOF")) == 1


def test_engine_arp_conflict_from_sniffer(seeded_db):
    _clear()
    state = SnifferState()
    state.arp.observe("192.168.1.9", "aa:aa:aa:aa:aa:aa")
    state.arp.observe("192.168.1.9", "bb:bb:bb:bb:bb:bb")
    summary = {"scan_id": 1, "new_devices": [], "joined": [], "present": []}
    engine.evaluate(summary, sniffer_state=state)
    conflicts = _alerts("ARP_SPOOF")
    assert len(conflicts) == 1 and "192.168.1.9" in conflicts[0]["detail"]


# --- port scan from tracker --------------------------------------------------
def test_engine_port_scan_from_sniffer(seeded_db):
    _clear()
    state = SnifferState()
    for port in range(20):                 # 20 distinct ports (threshold 15)
        state.ports.observe("192.168.1.77", 1000 + port)
    summary = {"scan_id": 1, "new_devices": [], "joined": [], "present": []}
    engine.evaluate(summary, sniffer_state=state)
    ps = _alerts("PORT_SCAN")
    assert len(ps) == 1 and "192.168.1.77" in ps[0]["detail"]


# --- IP churn ----------------------------------------------------------------
def test_engine_ip_churn(seeded_db):
    _clear()
    mac = "aa:00:00:00:00:20"
    did = _seed_device(mac, status="authorized")     # authorized so only churn fires
    # 3 distinct recent IPs -> at the default threshold (3).
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        repos.log_access(did, None, ip, "present")
    summary = {"scan_id": 1, "new_devices": [], "joined": [], "present": [mac]}
    engine.evaluate(summary)
    assert len(_alerts("IP_CHURN")) == 1


# --- service anomaly ---------------------------------------------------------
def test_engine_service_anomaly(seeded_db):
    _clear()
    mac = "aa:00:00:00:00:21"
    did = _seed_device(mac, status="authorized")
    repos.set_device_profile(did, "Linux", [80, 3389])   # 3389 is on the watchlist
    summary = {"scan_id": 1, "new_devices": [], "joined": [], "present": [mac]}
    engine.evaluate(summary)
    anomalies = _alerts("SERVICE_ANOMALY")
    assert len(anomalies) == 1 and "3389" in anomalies[0]["detail"]
