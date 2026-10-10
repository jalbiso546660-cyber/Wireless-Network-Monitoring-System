"""
Alerts view + acknowledge/resolve actions.
"""
from data import repos

CSRF = {"_csrf_token": "test-csrf-token"}


def test_alerts_page_lists_alerts(client, seeded_db, login):
    login(client, "viewer")
    resp = client.get("/alerts")
    assert resp.status_code == 200
    assert b"Seed alert" in resp.data          # the seeded alert renders


def test_monitor_can_acknowledge(client, seeded_db, login):
    login(client, "monitor")
    aid = seeded_db["alert_id"]
    resp = client.post(f"/alerts/{aid}/ack", data=CSRF)
    assert resp.status_code == 302
    assert repos.get_alert(aid)["status"] == "acknowledged"


def test_monitor_can_resolve_with_note(client, seeded_db, login):
    login(client, "monitor")
    aid = seeded_db["alert_id"]
    client.post(f"/alerts/{aid}/resolve", data={**CSRF, "note": "false alarm"})
    row = repos.get_alert(aid)
    assert row["status"] == "resolved"
    assert row["resolution_note"] == "false alarm"     # accountability recorded


def test_viewer_cannot_acknowledge(client, seeded_db, login):
    login(client, "viewer")
    aid = seeded_db["alert_id"]
    resp = client.post(f"/alerts/{aid}/ack", data=CSRF)
    assert resp.status_code == 403
    assert repos.get_alert(aid)["status"] == "new"     # unchanged


def test_ack_missing_alert_is_404(client, seeded_db, login):
    login(client, "admin")
    assert client.post("/alerts/999999/ack", data=CSRF).status_code == 404


def test_alert_status_filter(client, seeded_db, login):
    login(client, "admin")
    # Seeded alert is 'new' -> shows under new, not under resolved.
    assert b"Seed alert" in client.get("/alerts?status=new").data
    assert b"Seed alert" not in client.get("/alerts?status=resolved").data


def test_alert_severity_filter(client, seeded_db, login):
    login(client, "admin")
    from data import db
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "crit one")
    repos.insert_alert("UNAUTH_NEW", "low", "low one")
    crit = client.get("/alerts?severity=critical").data
    assert b"crit one" in crit and b"low one" not in crit


def test_alert_detail_page_shows_evidence(client, seeded_db, login):
    login(client, "admin")
    aid = seeded_db["alert_id"]
    did = seeded_db["device_id"]
    repos.log_access(did, None, "192.168.1.50", "present")
    resp = client.get(f"/alerts/{aid}")
    assert resp.status_code == 200
    assert b"Triggering evidence" in resp.data
    assert b"Seed alert" in resp.data


def test_get_unread_count_is_severity_weighted(seeded_db):
    from data import db
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")   # weight 8
    repos.insert_alert("UNAUTH_NEW", "high", "h")         # weight 4
    repos.insert_alert("IP_CHURN", "medium", "m")         # weight 2
    u = repos.get_unread_count()
    assert u["count"] == 3
    assert u["weight"] == 8 + 4 + 2
    assert u["top_severity"] == "critical"                # colours the nav badge


def test_nav_badge_renders_unread_count(client, seeded_db, login):
    from data import db
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    login(client, "viewer")
    resp = client.get("/dashboard")
    # The Alerts nav link carries a pill badge with the unread count.
    assert b"rounded-pill" in resp.data


def test_alert_detail_is_escaped(client, seeded_db, login):
    """Alert titles/details are attacker-influenced (device/vendor strings), so
    they must render escaped."""
    login(client, "admin")
    repos.insert_alert("UNAUTH_NEW", "low", "<script>alert(1)</script>",
                       detail="<b>x</b>")
    resp = client.get("/alerts")
    assert b"<script>alert(1)</script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data
