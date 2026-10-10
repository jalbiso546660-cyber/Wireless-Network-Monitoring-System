"""
Pagination on the /devices and /alerts list pages.
"""
import math

from data import db, repos
from web.routes.devices import _PER_PAGE as DEV_PER_PAGE
from web.routes.devices import _HISTORY_PER_PAGE, _HISTORY_PER_PAGE_VIEWER
from web.routes.alerts import _PER_PAGE as ALERT_PER_PAGE


def _seed_devices(n):
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")
    for i in range(n):
        repos.upsert_device(f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}",
                            f"192.168.9.{i % 254 + 1}", f"h{i}", "V")


def _seed_alerts(n):
    db.execute("DELETE FROM alerts")
    for i in range(n):
        repos.insert_alert("NEW_DEVICE", "low", f"alert {i}")


def _count_device_links(data: bytes) -> int:
    return data.count(b'href="/devices/')


# --- repo layer --------------------------------------------------------------
def test_query_devices_respects_limit_and_offset(seeded_db):
    _seed_devices(30)
    assert repos.count_devices_filtered() == 30
    assert len(repos.query_devices(limit=25, offset=0)) == 25
    assert len(repos.query_devices(limit=25, offset=25)) == 5     # last page


def test_count_alerts(seeded_db):
    _seed_alerts(30)
    assert repos.count_alerts() == 30
    assert len(repos.get_alerts(limit=25, offset=0)) == 25
    assert len(repos.get_alerts(limit=25, offset=25)) == 5


# --- devices page ------------------------------------------------------------
def test_devices_page_paginates(client, seeded_db, login):
    n = DEV_PER_PAGE * 2 + 2                         # 2 full pages + a partial
    remainder = n - DEV_PER_PAGE * 2
    _seed_devices(n)
    login(client, "viewer")

    p1 = client.get("/devices")
    assert p1.status_code == 200
    assert b"pagination" in p1.data                 # control is shown
    assert _count_device_links(p1.data) == DEV_PER_PAGE     # first page is full

    last_page = math.ceil(n / DEV_PER_PAGE)
    plast = client.get("/devices", query_string={"page": last_page})
    assert plast.status_code == 200
    assert _count_device_links(plast.data) == remainder     # last page: leftovers


def test_devices_pagination_preserves_filter(client, seeded_db, login):
    # 30 devices, all unauthorized by default from upsert.
    _seed_devices(30)
    login(client, "viewer")
    resp = client.get("/devices", query_string={"status": "unauthorized", "page": 2})
    assert resp.status_code == 200
    # page-2 links must carry the status filter forward.
    assert b"status=unauthorized" in resp.data


def test_devices_no_pagination_when_few(client, seeded_db, login):
    _seed_devices(3)
    login(client, "viewer")
    resp = client.get("/devices")
    assert resp.status_code == 200
    assert b"pagination" not in resp.data           # hidden for a single page


# --- alerts page -------------------------------------------------------------
def test_alerts_page_paginates(client, seeded_db, login):
    _seed_alerts(ALERT_PER_PAGE * 3)
    login(client, "viewer")
    p1 = client.get("/alerts")
    assert p1.status_code == 200
    assert b"pagination" in p1.data
    p2 = client.get("/alerts", query_string={"page": 2})
    assert p2.status_code == 200
    start = ALERT_PER_PAGE + 1                       # second page starts here
    assert (f"Showing {start}".encode()) in p2.data


# --- device access history ---------------------------------------------------
def test_access_history_paginates(client, seeded_db, login):
    """Monitor/admin see _HISTORY_PER_PAGE (23) rows per page."""
    did = seeded_db["device_id"]
    n = _HISTORY_PER_PAGE * 2 + 3
    db.execute("DELETE FROM access_logs")
    for _ in range(n):
        repos.log_access(did, None, "192.168.1.50", "present")
    assert repos.count_access_history(did) == n
    assert len(repos.get_device_history(did, limit=_HISTORY_PER_PAGE)) == _HISTORY_PER_PAGE

    login(client, "admin")
    p1 = client.get(f"/devices/{did}")
    assert p1.status_code == 200
    assert b"pagination" in p1.data
    assert f"of {n}".encode() in p1.data

    p2 = client.get(f"/devices/{did}", query_string={"page": 2})
    assert p2.status_code == 200
    start = _HISTORY_PER_PAGE + 1
    assert f"Showing {start}".encode() in p2.data
    # Page links carry the device id.
    assert f"/devices/{did}?".encode() in p2.data


def test_access_history_viewer_gets_18_per_page(client, seeded_db, login):
    """A viewer sees a shorter page (19 rows) than monitor/admin (23)."""
    did = seeded_db["device_id"]
    n = _HISTORY_PER_PAGE_VIEWER * 2 + 3
    db.execute("DELETE FROM access_logs")
    for _ in range(n):
        repos.log_access(did, None, "192.168.1.50", "present")
    assert _HISTORY_PER_PAGE_VIEWER == 18

    login(client, "viewer")
    p1 = client.get(f"/devices/{did}")
    assert p1.status_code == 200
    assert f"of {n}".encode() in p1.data
    assert f"Showing 1–{_HISTORY_PER_PAGE_VIEWER}".encode("utf-8") in p1.data

    p2 = client.get(f"/devices/{did}", query_string={"page": 2})
    start = _HISTORY_PER_PAGE_VIEWER + 1
    assert f"Showing {start}".encode() in p2.data
