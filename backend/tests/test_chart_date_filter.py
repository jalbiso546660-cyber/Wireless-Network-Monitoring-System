"""
Date filter on every chart (?from=YYYY-MM-DD&to=YYYY-MM-DD).

With no range each endpoint keeps its original rolling default (covered by
test_charts.py); these tests prove a range actually restricts the data, picks a
sensible axis granularity, and rejects/normalises bad input.
"""
from datetime import date, datetime, timedelta

from data import db, repos


def _day(offset: int) -> str:
    return (date.today() - timedelta(days=offset)).isoformat()


def _alert_at(severity: str, days_ago: int, rule: str = "UNAUTH_NEW") -> None:
    aid = repos.insert_alert(rule, severity, f"{severity} {days_ago}d ago")
    db.execute("UPDATE alerts SET created_at = %s WHERE id = %s",
               (datetime.now() - timedelta(days=days_ago), aid))


# --- alerts ------------------------------------------------------------------
def test_alerts_by_severity_counts_only_the_range(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    _alert_at("critical", 1)          # inside a last-3-days window
    _alert_at("high", 20)             # outside it
    login(client, "viewer")
    d = client.get("/api/charts/alerts-by-severity",
                   query_string={"from": _day(2), "to": _day(0)}).get_json()
    counts = dict(zip(d["labels"], d["data"]))
    assert counts["critical"] == 1 and counts["high"] == 0
    assert d["range"] == {"from": _day(2), "to": _day(0)}


def test_alerts_by_rule_counts_only_the_range(client, seeded_db, login):
    db.execute("DELETE FROM alerts")
    _alert_at("critical", 0, rule="ARP_SPOOF")
    _alert_at("high", 40, rule="PORT_SCAN")
    login(client, "viewer")
    d = client.get("/api/charts/alerts-by-rule",
                   query_string={"from": _day(6), "to": _day(0)}).get_json()
    counts = dict(zip(d["labels"], d["data"]))
    assert counts[repos.rule_label("ARP_SPOOF")] == 1
    assert counts[repos.rule_label("PORT_SCAN")] == 0


def test_alerts_over_time_axis_spans_the_range(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/alerts-over-time",
                   query_string={"from": _day(9), "to": _day(0)}).get_json()
    assert len(d["labels"]) == 10                         # one point per day
    assert all(len(s["data"]) == 10 for s in d["series"])


# --- time-series granularity -----------------------------------------------
def test_short_range_is_hourly_and_long_range_is_daily(client, seeded_db, login):
    login(client, "viewer")
    today = client.get("/api/charts/occupancy",
                       query_string={"from": _day(0), "to": _day(0)}).get_json()
    assert today["granularity"] == "hour"
    assert 1 <= len(today["labels"]) <= 24                # today's hours so far

    month = client.get("/api/charts/occupancy",
                       query_string={"from": _day(29), "to": _day(0)}).get_json()
    assert month["granularity"] == "day"
    assert len(month["labels"]) == 30
    assert not any(month["quiet"])                        # no quiet band on a daily axis


def test_scan_history_honours_the_range(client, seeded_db, login):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM scan_sessions")
    old = db.execute("INSERT INTO scan_sessions (started_at, finished_at, devices_found) "
                     "VALUES (%s, %s, 7)",
                     (datetime.now() - timedelta(days=15), datetime.now() - timedelta(days=15)))
    assert old
    login(client, "viewer")
    recent = client.get("/api/charts/scan-history",
                        query_string={"from": _day(2), "to": _day(0)}).get_json()
    assert recent["data"] == []                           # the only scan is outside
    wide = client.get("/api/charts/scan-history",
                      query_string={"from": _day(20), "to": _day(0)}).get_json()
    assert 7.0 in wide["data"]                            # ...and inside this one


# --- device charts (devices seen during the period) -------------------------
def test_device_status_counts_devices_seen_in_range(client, seeded_db, login):
    db.execute("DELETE FROM devices")
    now = datetime.now()
    db.execute("INSERT INTO devices (mac_address, status, first_seen, last_seen) "
               "VALUES ('aa:00:00:00:00:01', 'authorized', %s, %s)", (now, now))
    db.execute("INSERT INTO devices (mac_address, status, first_seen, last_seen) "
               "VALUES ('aa:00:00:00:00:02', 'blocked', %s, %s)",
               (now - timedelta(days=60), now - timedelta(days=50)))
    login(client, "viewer")
    ranged = client.get("/api/charts/device-status",
                        query_string={"from": _day(6), "to": _day(0)}).get_json()
    assert dict(zip(ranged["labels"], ranged["data"])) == \
        {"authorized": 1, "unauthorized": 0, "flagged": 0}
    everyone = client.get("/api/charts/device-status").get_json()      # default = all
    assert sum(everyone["data"]) == 2


def test_vendor_distribution_honours_the_range(client, seeded_db, login):
    db.execute("DELETE FROM devices")
    now = datetime.now()
    db.execute("INSERT INTO devices (mac_address, vendor, first_seen, last_seen) "
               "VALUES ('aa:00:00:00:00:01', 'Recent', %s, %s)", (now, now))
    db.execute("INSERT INTO devices (mac_address, vendor, first_seen, last_seen) "
               "VALUES ('aa:00:00:00:00:02', 'Ancient', %s, %s)",
               (now - timedelta(days=90), now - timedelta(days=80)))
    login(client, "viewer")
    d = client.get("/api/charts/vendor-distribution",
                   query_string={"from": _day(6), "to": _day(0)}).get_json()
    assert d["labels"] == ["Recent"]


# --- input handling ----------------------------------------------------------
def test_no_range_keeps_the_default_window(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/occupancy").get_json()
    assert d["range"] is None and len(d["labels"]) == 24


def test_invalid_dates_fall_back_to_default(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/alerts-by-severity",
                   query_string={"from": "not-a-date", "to": "2026-13-45"})
    assert d.status_code == 200 and d.get_json()["range"] is None


def test_reversed_range_is_swapped(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/alerts-over-time",
                   query_string={"from": _day(0), "to": _day(4)}).get_json()
    assert d["range"] == {"from": _day(4), "to": _day(0)}
    assert len(d["labels"]) == 5


def test_huge_range_is_capped(client, seeded_db, login):
    login(client, "viewer")
    d = client.get("/api/charts/alerts-over-time",
                   query_string={"from": "2000-01-01", "to": _day(0)}).get_json()
    assert len(d["labels"]) <= 366
