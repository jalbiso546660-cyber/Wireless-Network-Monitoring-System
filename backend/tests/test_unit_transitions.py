"""
joined / present / left transition logic (test DB, no network).

These are the presence-state guarantees from data/repos.py:
  * a brand-new or returned device logs 'joined' on the scan it appears;
  * a device already online logs 'present' on subsequent scans;
  * a device missed for `offline_after_missed` consecutive scans is flipped
    offline and logs 'left' EXACTLY ONCE.

IMPORTANT TEST-DESIGN NOTE
--------------------------
reconcile_offline() counts "misses" as the number of scan_sessions whose
started_at is strictly AFTER a device's last_seen. MySQL DATETIME has
one-second resolution, so a test that simply loops persist_scan() many times
within the same wall-clock second would collapse all timestamps and 'left'
would never fire. That is a TEST artifact, not a product bug (real scans are
seconds/minutes apart). We therefore control time explicitly: either by
inserting scan_sessions with fixed started_at values, or by back-dating a
device's last_seen to simulate "this device stopped appearing".
"""
from data import db, repos

SUBNET = "192.168.1.0/24"
IFACE = "test0"


def _clear():
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM scan_sessions")
    db.execute("DELETE FROM devices")


def _dev(mac, ip):
    return {"mac": mac, "ip": ip, "hostname": "", "vendor": ""}


def _left_events(mac):
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM access_logs al JOIN devices d "
        "ON d.id = al.device_id WHERE d.mac_address = %s AND al.event = 'left'",
        (mac,))
    return row["c"]


# --- joined vs present -------------------------------------------------------
def test_new_devices_join_then_present(seeded_db):
    _clear()
    a, b = "aa:00:00:00:00:01", "aa:00:00:00:00:02"

    r1 = repos.persist_scan([_dev(a, "192.168.1.11"), _dev(b, "192.168.1.12")],
                            SUBNET, IFACE, missed_threshold=3)
    assert set(r1["joined"]) == {a, b}     # first sighting => joined
    assert r1["present"] == []
    assert set(r1["new_devices"]) == {a, b}

    r2 = repos.persist_scan([_dev(a, "192.168.1.11")], SUBNET, IFACE,
                            missed_threshold=3)
    assert r2["present"] == [a]            # A already online => present
    assert r2["joined"] == []
    assert r2["new_devices"] == []
    # B was not seen this round but hasn't crossed the miss threshold yet.
    assert repos.get_device_by_mac(b)["is_online"] == 1


def test_returning_device_rejoins(seeded_db):
    _clear()
    a = "aa:00:00:00:00:03"
    repos.persist_scan([_dev(a, "192.168.1.13")], SUBNET, IFACE, missed_threshold=1)
    # Force A offline (simulate it having 'left').
    did = repos.get_device_by_mac(a)["id"]
    repos.mark_device_offline(did)

    r = repos.persist_scan([_dev(a, "192.168.1.13")], SUBNET, IFACE, missed_threshold=1)
    assert r["joined"] == [a]              # reappearance after offline => joined
    assert r["new_devices"] == []          # but NOT a new device row


# --- 'left' threshold boundary (direct reconcile_offline) --------------------
def _make_online_device(mac, last_seen):
    did, _ = repos.upsert_device(mac, "10.0.0.9", None, None)
    db.execute("UPDATE devices SET is_online = 1, last_seen = %s WHERE id = %s",
               (last_seen, did))
    return did


def _add_scans(n, started_at):
    last = None
    for _ in range(n):
        last = db.execute(
            "INSERT INTO scan_sessions (started_at, triggered_by) "
            "VALUES (%s, 'scheduler')", (started_at,))
    return last


def test_left_fires_exactly_at_threshold_not_before(seeded_db):
    threshold = 3

    # --- one UNDER threshold: 2 misses, must NOT be marked left ---
    _clear()
    mac = "cc:00:00:00:00:01"
    _make_online_device(mac, "2020-01-01 00:00:00")
    scan_id = _add_scans(threshold - 1, "2020-01-01 01:00:00")   # 2 scans after
    left = repos.reconcile_offline(scan_id, threshold)
    assert mac not in left
    assert repos.get_device_by_mac(mac)["is_online"] == 1
    assert _left_events(mac) == 0

    # --- exactly AT threshold: 3 misses, must be marked left once ---
    _clear()
    mac = "cc:00:00:00:00:02"
    _make_online_device(mac, "2020-01-01 00:00:00")
    scan_id = _add_scans(threshold, "2020-01-01 01:00:00")       # 3 scans after
    left = repos.reconcile_offline(scan_id, threshold)
    assert mac in left
    assert repos.get_device_by_mac(mac)["is_online"] == 0
    assert _left_events(mac) == 1


def test_left_logged_exactly_once_across_a_scan_sequence(seeded_db):
    """End-to-end through the real persist_scan path.

    A and B both appear; then B disappears (we back-date its last_seen so every
    subsequent scan_session counts as a miss regardless of same-second timing).
    B must be marked 'left' exactly once and never again.
    """
    _clear()
    a, b = "bb:00:00:00:00:01", "bb:00:00:00:00:02"
    threshold = 3

    repos.persist_scan([_dev(a, "192.168.1.21"), _dev(b, "192.168.1.22")],
                       SUBNET, IFACE, missed_threshold=threshold)   # scan #1
    # B stops appearing: pin its last_seen far in the past.
    db.execute("UPDATE devices SET last_seen = '2000-01-01 00:00:00' "
               "WHERE mac_address = %s", (b,))

    r2 = repos.persist_scan([_dev(a, "192.168.1.21")], SUBNET, IFACE,
                            missed_threshold=threshold)             # scan #2
    assert b not in r2["left"]             # only 2 scans so far -> not yet

    r3 = repos.persist_scan([_dev(a, "192.168.1.21")], SUBNET, IFACE,
                            missed_threshold=threshold)             # scan #3
    assert b in r3["left"]                 # 3rd scan -> crosses threshold
    assert repos.get_device_by_mac(b)["is_online"] == 0

    r4 = repos.persist_scan([_dev(a, "192.168.1.21")], SUBNET, IFACE,
                            missed_threshold=threshold)             # scan #4
    assert b not in r4["left"]             # already offline -> not re-fired

    assert _left_events(b) == 1            # EXACTLY one 'left' row for B
    assert _left_events(a) == 0            # A never left
