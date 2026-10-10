"""
Module 3 — Device Management & Authorization: block reason, MAC-filter text,
merge (MAC-randomization mitigation), and the assembled device detail.
"""
from data import db, repos

CSRF = {"_csrf_token": "test-csrf-token"}


def _clear():
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")


# --- block reason ------------------------------------------------------------
def test_block_device_records_reason(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")
    repos.block_device(did, admin_id=None, reason="rogue AP")
    row = repos.get_device(did)
    assert row["status"] == "blocked" and row["block_reason"] == "rogue AP"


def test_authorize_clears_block_reason(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "h", "V")
    repos.block_device(did, None, "temp")
    repos.authorize_device(did, None)
    row = repos.get_device(did)
    assert row["status"] == "authorized" and row["block_reason"] is None


# --- generate_mac_filter -----------------------------------------------------
def test_generate_mac_filter(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:03", "10.0.0.3", "h", "V")
    text = repos.generate_mac_filter(did)
    assert "aa:00:00:00:00:03" in text and "MAC-address filter" in text
    assert repos.generate_mac_filter(999999) is None      # missing device


# --- merge_devices -----------------------------------------------------------
def test_merge_reassigns_history_and_deletes_duplicate(seeded_db):
    _clear()
    prim, _ = repos.upsert_device("aa:00:00:00:00:10", "10.0.0.10", "h", "V")
    dup, _ = repos.upsert_device("aa:00:00:00:00:11", "10.0.0.11", "h", "V")
    repos.log_access(dup, None, "10.0.0.11", "joined")
    aid = repos.insert_alert("UNAUTH_NEW", "high", "dup alert", device_id=dup)

    assert repos.merge_devices(prim, dup) is True
    assert repos.get_device(dup) is None                       # duplicate removed
    assert any(h["ip_address"] == "10.0.0.11"
               for h in repos.get_device_history(prim))         # history moved
    assert repos.get_alert(aid)["device_id"] == prim            # alert moved


def test_merge_guards(seeded_db):
    _clear()
    prim, _ = repos.upsert_device("aa:00:00:00:00:20", "10.0.0.20", "h", "V")
    assert repos.merge_devices(prim, prim) is False            # same id
    assert repos.merge_devices(prim, 999999) is False          # missing


# --- get_device_detail -------------------------------------------------------
def test_get_device_detail_assembles_everything(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:30", "10.0.0.30", "h", "V")
    repos.log_access(did, None, "10.0.0.30", "joined")
    repos.insert_alert("UNAUTH_NEW", "high", "x", device_id=did)
    repos.block_device(did, None, "why")

    view = repos.get_device_detail(did)
    assert view["device"]["id"] == did
    assert len(view["history"]) == 1
    assert len(view["alerts"]) == 1
    assert view["mac_filter"] and "aa:00:00:00:00:30" in view["mac_filter"]


# --- routes ------------------------------------------------------------------
def test_block_route_stores_reason(client, seeded_db, login):
    did = seeded_db["device_id"]
    login(client, "admin")
    resp = client.post(f"/devices/{did}/block",
                       data={**CSRF, "reason": "unknown vendor"})
    assert resp.status_code == 302
    assert repos.get_device(did)["block_reason"] == "unknown vendor"


def test_merge_route_folds_duplicate(client, seeded_db, login):
    prim = seeded_db["device_id"]
    dup, _ = repos.upsert_device("aa:00:00:00:00:40", "10.0.0.40", "h", "V")
    login(client, "admin")
    resp = client.post(f"/devices/{prim}/merge",
                       data={**CSRF, "duplicate_mac": "aa:00:00:00:00:40"})
    assert resp.status_code == 302
    assert repos.get_device(dup) is None
