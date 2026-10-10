"""
Chart JSON endpoints (/api/charts/*). Asserts the exact shape charts.js expects.
Phase 1: occupancy (4.2/7.1) and alerts-by-severity (6.1/7.2).
"""
from datetime import datetime

from data import db, repos


# --- occupancy (4.2 / 7.1) ---------------------------------------------------
def test_occupancy_shape_and_zero_fill(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/occupancy", query_string={"hours": 24}).get_json()
    assert len(d["labels"]) == 24                       # contiguous hourly axis
    assert len(d["data"]) == 24 and len(d["quiet"]) == 24
    assert all(isinstance(v, int) for v in d["data"])   # integer counts
    assert all(isinstance(q, bool) for q in d["quiet"])


def test_occupancy_counts_distinct_devices_this_hour(client, seeded_db, login):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")
    d1, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")
    d2, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "h", "V")
    repos.log_access(d1, None, "10.0.0.1", "joined")
    repos.log_access(d1, None, "10.0.0.1", "present")     # same device, not double
    repos.log_access(d2, None, "10.0.0.2", "present")
    login(client, "viewer")
    d = client.get("/api/charts/occupancy").get_json()
    assert d["data"][-1] == 2                             # current hour: 2 distinct


def test_occupancy_quiet_band_reflects_settings(client, seeded_db, login):
    repos.set_setting("quiet_hours_start", "00:00")
    repos.set_setting("quiet_hours_end", "05:00")
    login(client, "viewer")
    d = client.get("/api/charts/occupancy").get_json()
    # every labelled hour < 05:00 is flagged quiet.
    for label, q in zip(d["labels"], d["quiet"]):
        assert q == (label < "05:00")


# --- alerts by severity (6.1 / 7.2) -----------------------------------------
def test_alerts_by_severity_fixed_order_zero_filled(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    repos.insert_alert("UNAUTH_NEW", "high", "h")
    login(client, "viewer")
    d = client.get("/api/charts/alerts-by-severity", query_string={"days": 7}).get_json()
    assert d["labels"] == ["low", "medium", "high", "critical"]   # never re-sorted
    assert d["data"] == [0, 0, 1, 1]                               # zero-filled


def test_alerts_by_severity_open_only(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    aid = repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    repos.resolve_alert(aid, 1)                       # resolved -> not "open"
    repos.insert_alert("UNAUTH_NEW", "high", "h")     # new -> open
    login(client, "viewer")
    all_d = client.get("/api/charts/alerts-by-severity").get_json()
    open_d = client.get("/api/charts/alerts-by-severity", query_string={"open": 1}).get_json()
    assert all_d["data"] == [0, 0, 1, 1]              # both counted
    assert open_d["data"] == [0, 0, 1, 0]             # resolved critical excluded


# --- alerts over time (6.2) --------------------------------------------------
def test_alerts_over_time_shape_and_series(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")     # today
    login(client, "viewer")
    d = client.get("/api/charts/alerts-over-time", query_string={"days": 30}).get_json()
    assert len(d["labels"]) == 30
    assert [s["severity"] for s in d["series"]] == ["low", "medium", "high", "critical"]
    for s in d["series"]:
        assert len(s["data"]) == 30
    crit = next(s for s in d["series"] if s["severity"] == "critical")
    assert crit["data"][-1] == 1                            # today's bucket


# --- alerts by rule (6.3) ----------------------------------------------------
def test_alerts_by_rule_all_eight_sorted_desc(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("PORT_SCAN", "high", "p1")
    repos.insert_alert("PORT_SCAN", "high", "p2")
    repos.insert_alert("UNAUTH_NEW", "high", "u")
    login(client, "viewer")
    d = client.get("/api/charts/alerts-by-rule", query_string={"days": 30}).get_json()
    assert len(d["labels"]) == 8                            # every rule shown
    # Labels are the plain-English rule names, not the internal codes.
    assert set(d["labels"]) == {repos.rule_label(c) for c in (
        "UNAUTH_NEW", "UNAUTH_RETURN", "BLOCKED_SEEN", "ARP_SPOOF",
        "PORT_SCAN", "OFF_HOURS_JOIN", "IP_CHURN", "SERVICE_ANOMALY")}
    assert d["labels"][0] == repos.rule_label("PORT_SCAN") and d["data"][0] == 2
    assert d["data"] == sorted(d["data"], reverse=True)
    assert d["data"].count(0) == 6                          # zero-count rules still appear


# --- device status (3.1) -----------------------------------------------------
def test_device_status_fixed_order(client, seeded_db, login):
    db.execute("DELETE FROM devices")
    a, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")
    b, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "h", "V")
    repos.authorize_device(a, None)          # authorized
    repos.block_device(b, None, "x")         # blocked; none unauthorized
    login(client, "viewer")
    d = client.get("/api/charts/device-status").get_json()
    assert d["labels"] == ["authorized", "unauthorized", "flagged"]   # UI wording
    assert d["data"] == [1, 0, 1]            # zero-filled unauthorized


# --- vendor distribution (3.2) ----------------------------------------------
def test_vendor_distribution_folds_tail_into_other(client, seeded_db, login):
    db.execute("DELETE FROM devices")
    # 12 distinct vendors, one device each -> limit=8 keeps 8, folds 4 into Other.
    for i in range(12):
        repos.upsert_device(f"aa:00:00:00:00:{i:02x}", f"10.0.0.{i}", "h", f"Vendor{i:02d}")
    login(client, "viewer")
    d = client.get("/api/charts/vendor-distribution", query_string={"limit": 8}).get_json()
    assert len(d["labels"]) == 9 and d["labels"][-1] == "Other"   # never a 9th real bar
    assert d["data"][-1] == 4                                     # the folded tail
    assert sum(d["data"]) == 12


# --- scan history (2.1) — hourly average, gap-filled -------------------------
def test_scan_history_hourly_average(client, seeded_db, login):
    db.execute("DELETE FROM scan_sessions")
    # Three scans in the SAME past hour -> one bucket, avg (2+5+3)/3 = 3.3.
    for n in (2, 5, 3):
        db.execute("INSERT INTO scan_sessions (started_at, finished_at, triggered_by, "
                   "devices_found) VALUES (NOW() - INTERVAL 2 HOUR, NOW() - INTERVAL 2 HOUR, "
                   "'scheduler', %s)", (n,))
    login(client, "viewer")
    d = client.get("/api/charts/scan-history", query_string={"hours": 24}).get_json()
    assert len(d["labels"]) == 24 and len(d["data"]) == 24    # contiguous hourly axis
    assert round(sum(d["data"]), 1) == 3.3                    # one bucket's average
    assert d["data"].count(0) == 23                           # other hours gap-filled to 0


def test_scan_history_empty_when_never_scanned(client, seeded_db, login):
    db.execute("DELETE FROM scan_sessions")
    login(client, "viewer")
    d = client.get("/api/charts/scan-history").get_json()
    assert d["labels"] == [] and d["data"] == []              # -> empty-state message


# --- presence timeline (4.1) — the floating-bar transform -------------------
def test_presence_pairs_join_to_left(client, seeded_db, login):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")
    did, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "host-x", "V")
    for ts, ev in [("2026-06-15 09:00:00", "joined"),
                   ("2026-06-15 10:00:00", "present"),
                   ("2026-06-15 11:00:00", "left")]:
        db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
                   "VALUES (%s, %s, %s, %s)", (did, "10.0.0.1", ev, ts))
    login(client, "viewer")
    d = client.get("/api/charts/presence-timeline",
                   query_string={"date": "2026-06-15"}).get_json()
    assert d["labels"] == ["host-x"]
    assert len(d["bars"]) == 1
    b = d["bars"][0]
    assert b["x"] == [540.0, 660.0]                  # 09:00 -> 11:00 in minutes
    assert b["join"] == "09:00" and b["leave"] == "11:00" and b["dur"] == "2h 0m"
    assert b["ip"] == "10.0.0.1"
    assert d["x_min"] == 540 and d["x_max"] == 720   # axis fitted to 09:00-12:00


def test_presence_coalesces_short_flaps(client, seeded_db, login):
    """Two sessions a couple of minutes apart (a scan-jitter flap) merge into one
    bar; sessions far apart stay separate."""
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")
    did, _ = repos.upsert_device("aa:00:00:00:00:03", "10.0.0.3", "host-z", "V")
    # flap: 09:00-09:02 then 09:04-09:06 (2-min gap < ~4-min threshold) -> merge
    # separate: 09:30-09:35 (28-min gap) -> its own bar
    for ts, ev in [("2026-06-15 09:00:00", "joined"), ("2026-06-15 09:02:00", "left"),
                   ("2026-06-15 09:04:00", "joined"), ("2026-06-15 09:06:00", "left"),
                   ("2026-06-15 09:30:00", "joined"), ("2026-06-15 09:35:00", "left")]:
        db.execute("INSERT INTO access_logs (device_id, ip_address, event, seen_at) "
                   "VALUES (%s, '10.0.0.3', %s, %s)", (did, ev, ts))
    login(client, "viewer")
    d = client.get("/api/charts/presence-timeline",
                   query_string={"date": "2026-06-15"}).get_json()
    assert len(d["bars"]) == 2                        # flap merged, gap kept
    assert d["bars"][0]["x"] == [540.0, 546.0]        # 09:00 -> 09:06 (merged)
    assert d["bars"][1]["x"] == [570.0, 575.0]        # 09:30 -> 09:35 (separate)


def test_presence_still_online_runs_to_now(client, seeded_db, login):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")
    did, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "host-y", "V")
    db.execute("INSERT INTO access_logs (device_id, ip_address, event) "
               "VALUES (%s, '10.0.0.2', 'joined')", (did,))
    db.execute("INSERT INTO access_logs (device_id, ip_address, event) "
               "VALUES (%s, '10.0.0.2', 'present')", (did,))     # today, no 'left'
    login(client, "viewer")
    d = client.get("/api/charts/presence-timeline").get_json()   # defaults to today
    assert d["labels"] == ["host-y"]
    assert d["bars"][0]["leave"] == "online"          # open segment -> now


def test_presence_empty_day(client, seeded_db, login):
    db.execute("DELETE FROM access_logs")
    login(client, "viewer")
    d = client.get("/api/charts/presence-timeline",
                   query_string={"date": "2020-01-01"}).get_json()
    assert d["labels"] == [] and d["bars"] == []


def test_charts_require_login(client, seeded_db):
    for path in ("/api/charts/occupancy", "/api/charts/alerts-by-severity",
                 "/api/charts/alerts-over-time", "/api/charts/alerts-by-rule",
                 "/api/charts/device-status", "/api/charts/vendor-distribution",
                 "/api/charts/scan-history", "/api/charts/presence-timeline"):
        assert client.get(path).status_code == 302
