"""
Reports (Module 8): CSV/PDF generation (reports/generator.py), filters, the
self-documenting PDF header, and the download routes.
"""
from data import db, repos
from reports import generator


def test_csv_has_header_and_rows(seeded_db):
    data, mime = generator.download_report("devices", "csv")
    assert mime == "text/csv"
    text = data.decode("utf-8-sig")
    assert text.splitlines()[0].startswith("MAC,Label,Last IP")
    assert repos.list_devices()[0]["mac_address"] in text


def test_pdf_is_a_pdf(seeded_db):
    data, mime = generator.download_report("devices", "pdf")
    assert mime == "application/pdf"
    assert data[:5] == b"%PDF-" and len(data) > 500


def test_all_kinds_build_in_both_formats(seeded_db):
    for kind, _title in generator.REPORT_META:
        for fmt in ("csv", "pdf"):
            data, _mime = generator.download_report(kind, fmt)
            assert data


# --- filters -----------------------------------------------------------------
def test_device_inventory_status_filter(seeded_db):
    db.execute("DELETE FROM devices")
    a, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")
    b, _ = repos.upsert_device("aa:00:00:00:00:02", "10.0.0.2", "h", "V")
    repos.block_device(b, None, "x")
    ds = generator.build_device_inventory(status="blocked")
    macs = [r[0] for r in ds["rows"]]
    assert macs == ["aa:00:00:00:00:02"]                 # only the blocked one


def test_alert_summary_severity_filter(seeded_db):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    repos.insert_alert("UNAUTH_NEW", "low", "l")
    ds = generator.build_alert_summary(severity="critical")
    assert len(ds["rows"]) == 1 and ds["rows"][0][1] == "critical"


# --- embedded PDF charts (8.1 / 8.2) ----------------------------------------
def test_alert_summary_has_severity_chart(seeded_db):
    db.execute("DELETE FROM alerts")
    repos.insert_alert("BLOCKED_SEEN", "critical", "c")
    repos.insert_alert("UNAUTH_NEW", "high", "h")
    ds = generator.build_alert_summary()
    assert ds["chart"]["labels"] == ["low", "medium", "high", "critical"]
    assert ds["chart"]["data"] == [0, 0, 1, 1]
    assert ds["chart"]["colors"][3] == "#dc2626"     # critical red matches CSS/JS
    pdf = generator.render_pdf(ds, "alice")
    assert pdf[:5] == b"%PDF-" and len(pdf) > 500


def test_device_inventory_has_status_chart(seeded_db):
    db.execute("DELETE FROM devices")
    a, _ = repos.upsert_device("aa:00:00:00:00:01", "10.0.0.1", "h", "V")
    repos.authorize_device(a, None)
    ds = generator.build_device_inventory()
    assert ds["chart"]["labels"] == ["authorized", "unauthorized", "flagged"]   # UI wording
    assert ds["chart"]["data"] == [1, 0, 0]
    assert ds["chart"]["colors"][0] == "#0d6efd"     # accent matches on-screen 3.1
    pdf = generator.render_pdf(ds, "bob")
    assert pdf[:5] == b"%PDF-"


# --- self-documenting PDF header --------------------------------------------
def test_pdf_header_records_generator_and_filters(seeded_db):
    ds = generator.build_alert_summary(severity="high")
    pdf = generator.render_pdf(ds, generated_by="alice")
    # PDF text is compressed, so assert via the CSV/dataset instead + a smoke
    # check that render succeeds and is non-trivial.
    assert pdf[:5] == b"%PDF-" and len(pdf) > 500
    # The filter summary the header prints:
    assert "severity: high" in generator._fmt_filters(ds["filters"])


# --- routes ------------------------------------------------------------------
def test_download_route_csv(client, seeded_db, login):
    login(client, "monitor")              # generating a report is Admin+Monitor
    resp = client.get("/reports/devices.csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "pwnm_devices_" in resp.headers["Content-Disposition"]


def test_download_route_is_view_only_for_viewer(client, seeded_db, login):
    """Module 8 contract: a viewer may open /reports but NOT export/generate."""
    login(client, "viewer")
    assert client.get("/reports").status_code == 200          # can view the page
    assert client.get("/reports/devices.csv").status_code == 403   # cannot export


def test_download_route_pdf_with_filters(client, seeded_db, login):
    login(client, "admin")
    resp = client.get("/reports/alerts.pdf", query_string={"severity": "critical"})
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data[:5] == b"%PDF-"


def test_download_route_rejects_unknown(client, seeded_db, login):
    login(client, "monitor")              # allowed role, so we reach the 404 gate
    assert client.get("/reports/nonsense.csv").status_code == 404
    assert client.get("/reports/devices.xml").status_code == 404
