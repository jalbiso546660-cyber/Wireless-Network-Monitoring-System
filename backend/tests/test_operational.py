"""
Operational features:
  * Log retention — prune_old_records bounds access_logs/scan_sessions growth.
  * Configuration audit trail — who changed which setting, when, old -> new.
"""
import scheduler
from data import db, repos

CSRF = {"_csrf_token": "test-csrf-token"}


# --- log retention (§7) ------------------------------------------------------
def test_prune_old_records_removes_old_keeps_recent(seeded_db):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM scan_sessions")
    db.execute("DELETE FROM devices")
    did, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")

    db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
               "VALUES (%s, '10.0.0.1', 'present', NOW() - INTERVAL 100 DAY)", (did,))
    db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
               "VALUES (%s, '10.0.0.1', 'present', NOW())", (did,))
    db.execute("INSERT INTO scan_sessions (started_at, finished_at, triggered_by, "
               "devices_found) VALUES (NOW() - INTERVAL 100 DAY, NOW() - INTERVAL 100 DAY, "
               "'scheduler', 1)")
    db.execute("INSERT INTO scan_sessions (started_at, finished_at, triggered_by, "
               "devices_found) VALUES (NOW(), NOW(), 'scheduler', 1)")

    removed = repos.prune_old_records(90)
    assert removed["access_logs"] == 1 and removed["scan_sessions"] == 1
    assert repos.count_access_history(did) == 1                    # recent one kept
    assert db.query_one("SELECT COUNT(*) c FROM scan_sessions")["c"] == 1


def test_scheduler_prune_job_uses_setting_and_never_raises(seeded_db):
    db.execute("DELETE FROM access_logs")
    did, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "h", "V")
    db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
               "VALUES (%s, '10.0.0.2', 'present', NOW() - INTERVAL 200 DAY)", (did,))
    scheduler.prune_old_records()                                  # reads log_retention_days=90
    assert repos.count_access_history(did) == 0                    # 200-day-old log pruned


def test_retention_setting_is_validated(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={**CSRF, "log_retention_days": "0"})   # below min 1
    assert repos.get_int_setting("log_retention_days", 0) == 90    # rejected, unchanged


# --- configuration audit trail (§8) -----------------------------------------
def test_setting_change_is_audited(client, seeded_db, login):
    login(client, "admin")
    resp = client.post("/admin/settings", data={**CSRF, "scan_interval_seconds": "45"})
    assert resp.status_code == 302
    changes = repos.recent_setting_changes(10)
    hit = next((c for c in changes if c["setting_key"] == "scan_interval_seconds"), None)
    assert hit is not None
    assert hit["old_value"] == "60" and hit["new_value"] == "45"
    assert hit["changed_by"] == "admin"                           # who changed it


def test_noop_setting_change_not_audited(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={**CSRF, "scan_interval_seconds": "60"})  # same value
    assert repos.recent_setting_changes(10) == []                 # no noise logged


def test_settings_page_shows_audit_trail(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={**CSRF, "offline_after_missed": "5"})
    resp = client.get("/admin/settings")
    assert b"Recent configuration changes" in resp.data
    assert b"offline_after_missed" in resp.data


def test_record_setting_change_ignores_noop(seeded_db):
    db.execute("DELETE FROM setting_audit")
    repos.record_setting_change("x", "5", "5", 1)                 # unchanged
    repos.record_setting_change("x", "5", "9", 1)                 # changed
    changes = repos.recent_setting_changes(10)
    assert len(changes) == 1 and changes[0]["new_value"] == "9"
