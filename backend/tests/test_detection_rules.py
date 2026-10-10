"""
Unit tests for detection/rules.py + core/sniffer.py trackers — pure logic, no
DB, no network. Every rule is driven by synthetic input, including the exact
threshold boundaries.
"""
from datetime import datetime

import pytest

from core.sniffer import ArpTable, PortScanTracker
from detection import rules


def _dev(mac="aa:bb:cc:dd:ee:ff", status="unauthorized", vendor="Acme",
         ip="192.168.1.10", id=1):
    return {"id": id, "mac": mac, "status": status, "vendor": vendor, "last_ip": ip}


# --- 5.2 unauthorized rules --------------------------------------------------
def test_rule_unauth_new_is_high():
    a = rules.rule_unauth_new(_dev())
    assert a["rule_code"] == "UNAUTH_NEW"
    assert a["severity"] == "high"          # spec: brand-new device is HIGH
    assert a["device_id"] == 1


def test_rule_unauth_return_only_for_unauthorized():
    assert rules.rule_unauth_return(_dev(status="unauthorized"))["rule_code"] == "UNAUTH_RETURN"
    assert rules.rule_unauth_return(_dev(status="authorized")) is None
    assert rules.rule_unauth_return(_dev(status="blocked")) is None


def test_rule_blocked_seen_only_for_blocked():
    a = rules.rule_blocked_seen(_dev(status="blocked"))
    assert a["rule_code"] == "BLOCKED_SEEN" and a["severity"] == "critical"
    assert rules.rule_blocked_seen(_dev(status="unauthorized")) is None


# --- 5.3 ARP spoofing --------------------------------------------------------
def test_rule_arp_spoof_gateway_change():
    a = rules.rule_arp_spoof("192.168.1.1", "de:ad:be:ef:00:99", "aa:bb:cc:dd:ee:ff")
    assert a["rule_code"] == "ARP_SPOOF" and a["severity"] == "critical"


def test_rule_arp_spoof_silent_when_unchanged_or_no_baseline():
    assert rules.rule_arp_spoof("192.168.1.1", "AA:BB:CC:DD:EE:FF",
                                "aa:bb:cc:dd:ee:ff") is None   # case-insensitive same
    assert rules.rule_arp_spoof("192.168.1.1", "aa:bb:cc:dd:ee:ff", None) is None
    assert rules.rule_arp_spoof("192.168.1.1", None, "aa:bb:cc:dd:ee:ff") is None


def test_rule_arp_conflict_two_macs():
    a = rules.rule_arp_conflict("192.168.1.5", ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"])
    assert a["rule_code"] == "ARP_SPOOF" and a["severity"] == "critical"


def test_rule_arp_conflict_single_mac_is_none():
    assert rules.rule_arp_conflict("192.168.1.5", ["aa:aa:aa:aa:aa:aa"]) is None
    assert rules.rule_arp_conflict("192.168.1.5",
                                   ["aa:aa:aa:aa:aa:aa", "aa:aa:aa:aa:aa:aa"]) is None


# --- quiet hours -------------------------------------------------------------
@pytest.mark.parametrize("hhmm, start, end, inside", [
    ("00:00", "00:00", "05:00", True),
    ("04:59", "00:00", "05:00", True),
    ("05:00", "00:00", "05:00", False),
    ("05:01", "00:00", "05:00", False),
    ("23:30", "22:00", "05:00", True),
    ("02:00", "22:00", "05:00", True),
    ("21:59", "22:00", "05:00", False),
])
def test_within_quiet_hours_boundaries(hhmm, start, end, inside):
    now_t = rules.parse_hhmm(hhmm)
    assert rules.within_quiet_hours(now_t, rules.parse_hhmm(start),
                                    rules.parse_hhmm(end)) is inside


def test_rule_off_hours_join_only_inside_window():
    inside = datetime(2026, 1, 1, 2, 0, 0)
    assert rules.rule_off_hours_join(_dev(), inside, "00:00", "05:00")["rule_code"] == "OFF_HOURS_JOIN"
    outside = datetime(2026, 1, 1, 12, 0, 0)
    assert rules.rule_off_hours_join(_dev(), outside, "00:00", "05:00") is None


# --- IP churn ----------------------------------------------------------------
def test_rule_ip_churn_boundary():
    # threshold 3: exactly at fires, one under does not.
    assert rules.rule_ip_churn(_dev(), 3, 3, 10)["rule_code"] == "IP_CHURN"
    assert rules.rule_ip_churn(_dev(), 4, 3, 10)["rule_code"] == "IP_CHURN"
    assert rules.rule_ip_churn(_dev(), 2, 3, 10) is None


# --- service anomaly ---------------------------------------------------------
def test_rule_service_anomaly_matches_watchlist():
    a = rules.rule_service_anomaly(_dev(), [80, 3389, 443], {22, 3389, 445})
    assert a["rule_code"] == "SERVICE_ANOMALY" and a["severity"] == "low"
    assert "3389" in a["detail"]


def test_rule_service_anomaly_no_match_is_none():
    assert rules.rule_service_anomaly(_dev(), [80, 443], {22, 3389}) is None


# --- port-scan tracker (core/sniffer.py) ------------------------------------
def test_port_scan_tracker_boundary():
    threshold, window = 15, 60
    t = PortScanTracker()
    for port in range(14):
        t.observe("10.0.0.5", 1000 + port, ts=100.0)
    assert t.offenders(threshold, window, now=100.0) == []

    t = PortScanTracker()
    for port in range(15):
        t.observe("10.0.0.5", 1000 + port, ts=100.0)
    assert t.offenders(threshold, window, now=100.0) == [("10.0.0.5", 15)]
    assert t.offenders(threshold, window, now=101.0) == []      # cooldown


def test_port_scan_tracker_window_expiry_and_distinct():
    t = PortScanTracker()
    for port in range(5):
        t.observe("10.0.0.9", 2000 + port, ts=0.0)
    assert t.offenders(5, 60, now=120.0) == []                  # aged out
    t2 = PortScanTracker()
    for _ in range(50):
        t2.observe("10.0.0.7", 80, ts=10.0)
    assert t2.offenders(15, 60, now=10.0) == []                 # 1 distinct port


# --- ARP table (core/sniffer.py) --------------------------------------------
def test_arp_table_flags_two_macs_on_one_ip():
    at = ArpTable()
    at.observe("192.168.1.1", "aa:aa:aa:aa:aa:aa", ts=100.0)
    at.observe("192.168.1.1", "bb:bb:bb:bb:bb:bb", ts=100.0)
    conflicts = at.conflicts(window=120, now=100.0)
    assert conflicts and conflicts[0][0] == "192.168.1.1"
    assert set(conflicts[0][1]) == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}


def test_arp_table_single_mac_no_conflict():
    at = ArpTable()
    at.observe("192.168.1.1", "aa:aa:aa:aa:aa:aa", ts=100.0)
    at.observe("192.168.1.1", "aa:aa:aa:aa:aa:aa", ts=100.0)
    assert at.conflicts(window=120, now=100.0) == []


def test_arp_table_conflict_expires():
    at = ArpTable()
    at.observe("192.168.1.1", "aa:aa:aa:aa:aa:aa", ts=0.0)
    at.observe("192.168.1.1", "bb:bb:bb:bb:bb:bb", ts=0.0)
    assert at.conflicts(window=120, now=300.0) == []            # both aged out
