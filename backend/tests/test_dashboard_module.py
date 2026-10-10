"""
Module 7 — Dashboard & Monitoring: summary, alerts-by-severity chart (replacing
the vendor chart), devices-over-time, the activity feed, and role panels.
"""
from data import db, repos


def _clear():
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM scan_sessions")
    db.execute("DELETE FROM devices")


# --- repo layer --------------------------------------------------------------
def test_get_summary(seeded_db):
    s = repos.get_summary()
    assert set(s["counts"]) >= {"online", "unauthorized", "blocked", "total"}
    assert "open_alerts" in s and "last_scan" in s


def test_chart_alerts_by_severity_ordered(seeded_db):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    repos.insert_alert("UNAUTH_NEW", "high", "h")
    rows = repos.chart_alerts_by_severity()
    assert [r["severity"] for r in rows] == ["low", "medium", "high", "critical"]
    counts = {r["severity"]: r["count"] for r in rows}
    assert counts["critical"] == 1 and counts["high"] == 1 and counts["low"] == 0


def test_chart_devices_over_time_oldest_first(seeded_db):
    _clear()
    s1 = repos.start_scan_session("192.168.1.0/24", "if"); repos.finish_scan_session(s1, 2)
    s2 = repos.start_scan_session("192.168.1.0/24", "if"); repos.finish_scan_session(s2, 5)
    rows = repos.chart_devices_over_time(10)
    assert [r["devices_found"] for r in rows] == [2, 5]        # oldest first


# --- polling API (tiles + activity; charts are served by /api/charts/*) ------
def test_api_summary_has_tiles_and_activity_not_charts(client, seeded_db, login):
    login(client, "viewer")
    data = client.get("/api/summary").get_json()
    assert "counts" in data and "open_alerts" in data and "activity" in data
    assert "charts" not in data                 # charts moved to /api/charts/*


def test_open_alerts_tile_counts_new_plus_acknowledged(seeded_db):
    db.execute("DELETE FROM alerts")
    a1 = repos.insert_alert("UNAUTH_NEW", "high", "n")     # new
    a2 = repos.insert_alert("IP_CHURN", "medium", "a")     # -> acknowledged
    repos.acknowledge_alert(a2, 1)
    repos.insert_alert("PORT_SCAN", "high", "r")           # will be resolved
    # resolve one so it is NOT counted
    resolved = repos.get_alerts(status="new")[0]["id"]
    repos.resolve_alert(resolved, 1)
    assert repos.count_open_alerts_broad() == 2            # new + acknowledged only


# --- dashboard page ----------------------------------------------------------
def test_dashboard_shows_the_two_charts_and_activity(client, seeded_db, login):
    login(client, "viewer")
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"chart-occupancy" in resp.data          # 7.1
    assert b"chart-open-severity" in resp.data       # 7.2
    assert b"Recent activity" in resp.data
    assert b"charts.js" in resp.data                 # charts wired up


def test_dashboard_role_panels(app, seeded_db, login):
    mon = app.test_client()
    login(mon, "monitor")
    assert b"Scan now" in mon.get("/dashboard").data      # monitor gets the control

    vw = app.test_client()
    login(vw, "viewer")
    body = vw.get("/dashboard").data
    assert b"read-only" in body.lower()                    # viewer sees the note (any casing)
    assert b'action="/scan/now"' not in body               # and no scan control


def test_healthz_is_public_and_reports_ok(client, seeded_db):
    """Liveness probe needs no auth and reports the DB status."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["database"] == "up"


# --- "Scan now" returns you to the page you were on -------------------------
def test_scan_now_returns_to_the_calling_page(app, seeded_db, login):
    """The sidebar button is on every page, so queuing a scan must not yank the
    user to the dashboard — it returns to the referring page."""
    c = app.test_client()
    login(c, "monitor")
    resp = c.post("/scan/now", data={"_csrf_token": "test-csrf-token"},
                  headers={"Referer": "http://localhost/alerts?status=new"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/alerts?status=new")


def test_scan_now_without_referrer_falls_back_to_dashboard(app, seeded_db, login):
    c = app.test_client()
    login(c, "monitor")
    resp = c.post("/scan/now", data={"_csrf_token": "test-csrf-token"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_scan_now_ignores_an_offsite_referrer(app, seeded_db, login):
    """Open-redirect guard: a foreign Referer never sends the user off-site."""
    c = app.test_client()
    login(c, "monitor")
    resp = c.post("/scan/now", data={"_csrf_token": "test-csrf-token"},
                  headers={"Referer": "https://evil.com/steal"})
    assert resp.status_code == 302
    assert "evil.com" not in resp.headers["Location"]


def test_scan_now_ajax_returns_json_ack(app, seeded_db, login):
    """The sidebar button posts with X-Requested-With and expects a small JSON
    ack (no redirect) so it can show live progress instead of reloading."""
    app.config["SCAN_TRIGGER"] = lambda user_id=None: True   # fake: scheduler is up
    c = app.test_client()
    login(c, "monitor")
    resp = c.post("/scan/now", data={"_csrf_token": "test-csrf-token"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.get_json() == {"queued": True}


def test_scan_now_ajax_reports_false_when_scheduler_is_down(app, seeded_db, login):
    app.config["SCAN_TRIGGER"] = None
    c = app.test_client()
    login(c, "monitor")
    resp = c.post("/scan/now", data={"_csrf_token": "test-csrf-token"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
    assert resp.status_code == 200
    assert resp.get_json() == {"queued": False}
