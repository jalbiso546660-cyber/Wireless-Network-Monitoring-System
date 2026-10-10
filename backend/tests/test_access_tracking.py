"""
Module 4 — Access Tracking & Logging: event classification, IP history,
date-range history, and the activity feed.
"""
import pytest

from data import db, repos


def _clear():
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")


# --- determine_event (pure) --------------------------------------------------
@pytest.mark.parametrize("seen, was_online, expected", [
    (True, False, "joined"),      # first appearance after offline / new
    (True, True, "present"),      # still here
    (False, True, "left"),        # gone (caller applies the miss threshold)
    (False, False, "left"),
])
def test_determine_event(seen, was_online, expected):
    assert repos.determine_event(seen, was_online) == expected


# --- get_ip_history (feeds the IP_CHURN rule) --------------------------------
def test_get_ip_history_distinct_ips(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:aa", "192.168.1.10", "h", "V")
    repos.log_access(did, None, "192.168.1.10", "joined")
    repos.log_access(did, None, "192.168.1.10", "present")
    repos.log_access(did, None, "192.168.1.20", "present")

    ips = {r["ip"]: r["hits"] for r in repos.get_ip_history(did)}
    assert set(ips) == {"192.168.1.10", "192.168.1.20"}   # distinct IPs
    assert ips["192.168.1.10"] == 2
    assert ips["192.168.1.20"] == 1


# --- get_device_history date range ------------------------------------------
def test_get_device_history_date_range(seeded_db):
    _clear()
    did, _ = repos.upsert_device("aa:00:00:00:00:bb", "10.0.0.1", "h", "V")
    for ts, ev in [("2026-01-01 00:00:00", "joined"),
                   ("2026-06-01 00:00:00", "present"),
                   ("2026-12-01 00:00:00", "left")]:
        db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
                   "VALUES (%s, %s, %s, %s)", (did, "10.0.0.1", ev, ts))

    assert len(repos.get_device_history(did)) == 3
    mid = repos.get_device_history(did, date_from="2026-03-01", date_to="2026-09-01")
    assert len(mid) == 1 and mid[0]["event"] == "present"


# --- get_activity_feed -------------------------------------------------------
def test_get_activity_feed_recent_first_with_mac(seeded_db):
    _clear()
    d1, _ = repos.upsert_device("aa:00:00:00:00:c1", "10.0.0.1", "h", "V")
    d2, _ = repos.upsert_device("aa:00:00:00:00:c2", "10.0.0.2", "h", "V")
    repos.log_access(d1, None, "10.0.0.1", "joined")
    repos.log_access(d2, None, "10.0.0.2", "joined")

    feed = repos.get_activity_feed(limit=10)
    assert len(feed) == 2
    assert "mac_address" in feed[0]        # joined to devices for display
    assert feed[0]["device_id"] == d2      # most recent first (id tiebreaker)
