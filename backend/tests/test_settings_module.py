"""
Module 9 — System Configuration: validation, interface selection, live apply.
"""
import pytest

from data import repos
from web.routes import settings as settings_route

CSRF = {"_csrf_token": "test-csrf-token"}


def test_reset_baseline_clears_gateway_mac(client, seeded_db, login):
    """Admin 'Reset baseline' clears the learned gateway MAC so the next scan
    re-learns it (recovery after a legitimate router change)."""
    repos.set_setting("gateway_mac_baseline", "aa:bb:cc:dd:ee:ff")
    login(client, "admin")
    resp = client.post("/admin/settings/reset-baseline", data=CSRF)
    assert resp.status_code == 302
    assert (repos.get_setting("gateway_mac_baseline") or "") == ""


# --- validate_setting (pure) -------------------------------------------------
@pytest.mark.parametrize("key, value, ok", [
    ("scan_interval_seconds", "60", True),
    ("scan_interval_seconds", "4", False),        # below min 5
    ("scan_interval_seconds", "999999", False),   # above max 3600
    ("scan_interval_seconds", "abc", False),      # not an int
    ("offline_after_missed", "3", True),
    ("offline_after_missed", "0", False),         # below min 1
    ("portscan_port_threshold", "15", True),
    ("portscan_port_threshold", "1", False),      # below min 2
    ("quiet_hours_start", "05:00", True),
    ("quiet_hours_start", "25:00", False),        # bad time
    ("monitor_subnet", "192.168.1.0/24", True),
    ("monitor_subnet", "not-a-subnet", False),
    ("gateway_mac_baseline", "aa:bb:cc:dd:ee:ff", True),   # unknown key passes through
])
def test_validate_setting(key, value, ok):
    result_ok, _ = repos.validate_setting(key, value)
    assert result_ok is ok


def test_set_setting_rejects_invalid(seeded_db):
    with pytest.raises(ValueError):
        repos.set_setting("scan_interval_seconds", "0")
    assert repos.get_int_setting("scan_interval_seconds", 0) == 60   # unchanged


def test_set_setting_stores_valid(seeded_db):
    repos.set_setting("scan_interval_seconds", 120)
    assert repos.get_int_setting("scan_interval_seconds", 0) == 120


def test_list_settings(seeded_db):
    keys = {r["setting_key"] for r in repos.list_settings()}
    assert "scan_interval_seconds" in keys and "monitor_subnet" in keys


def test_unauth_rate_limit_is_one_hour(seeded_db):
    # Spec conflict fixed: one alert per device per hour (3600s), not 300s.
    assert repos.get_int_setting("unauth_return_rate_limit_seconds", 0) == 3600


# --- select_interface (Module 9.3) ------------------------------------------
def test_select_interface_derives_subnet(seeded_db, monkeypatch):
    fake = [{"name": "Wi-Fi", "subnet_cidr": "10.9.8.0/24", "is_up": True, "is_virtual": False}]
    monkeypatch.setattr(settings_route.interfaces, "list_interfaces", lambda: fake)
    assert settings_route.select_interface("Wi-Fi") == "10.9.8.0/24"
    assert repos.get_setting("monitor_subnet") == "10.9.8.0/24"
    assert repos.get_setting("monitor_interface") == "Wi-Fi"


def test_select_interface_unknown_name(seeded_db, monkeypatch):
    monkeypatch.setattr(settings_route.interfaces, "list_interfaces", lambda: [])
    assert settings_route.select_interface("Nope") is None
    assert repos.get_setting("monitor_interface") == "Nope"        # name still stored


def test_choose_interface_route(client, seeded_db, login, monkeypatch):
    fake = [{"name": "eth42", "subnet_cidr": "172.16.0.0/16", "is_up": True, "is_virtual": False}]
    monkeypatch.setattr(settings_route.interfaces, "list_interfaces", lambda: fake)
    login(client, "admin")
    resp = client.post("/admin/settings/interface", data={**CSRF, "interface": "eth42"})
    assert resp.status_code == 302
    assert repos.get_setting("monitor_subnet") == "172.16.0.0/16"


# --- live apply of scan interval (Module 9.4) -------------------------------
def test_saving_interval_applies_live(client, seeded_db, login):
    called = {}
    client.application.config["APPLY_SCAN_INTERVAL"] = lambda s: called.setdefault("secs", s)
    login(client, "admin")
    resp = client.post("/admin/settings", data={**CSRF, "scan_interval_seconds": "30"})
    assert resp.status_code == 302
    assert repos.get_int_setting("scan_interval_seconds", 0) == 30
    assert called.get("secs") == 30       # rescheduled without a restart
