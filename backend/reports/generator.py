"""
reports/generator.py  — Module 8: Reporting

Build downloadable, date-filterable reports (CSV + PDF) from the data layer:

  * devices  — device inventory        (filter: status, date range)
  * access   — access history          (filter: device, date range)
  * alerts   — alert summary           (filter: severity, date range)

Each builder returns a DATASET dict — {title, headers, rows, filters} — and the
two renderers turn it into bytes. render_pdf prints a SELF-DOCUMENTING header
(title, generated-at, generated-by, and the filter criteria) so a printed report
stands on its own. download_report() ties a kind + format + filters together for
the web layer.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from data import repos

CSV_MIME = "text/csv"
PDF_MIME = "application/pdf"

_MAX_ROWS = 5000        # bound a single report

# Colours mirror pwnm.css / charts.js EXACTLY so the PDF charts match on-screen.
SEV_HEX = {"low": "#64748b", "medium": "#f59e0b", "high": "#ea580c", "critical": "#dc2626"}
ACCENT_HEX = "#0d6efd"
SEVERITY_ORDER = ("low", "medium", "high", "critical")
STATUS_ORDER = ("authorized", "unauthorized", "blocked")


def _bar_drawing(labels, data, hex_colors):
    """A small ReportLab vertical bar chart for embedding in a PDF."""
    dw = Drawing(440, 170)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 35, 25, 380, 120
    bc.data = [data]
    bc.categoryAxis.categoryNames = list(labels)
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = (max(data) + 1) if data and max(data) > 0 else 1
    bc.barWidth = 14
    bc.groupSpacing = 12
    for i, c in enumerate(hex_colors):
        bc.bars[(0, i)].fillColor = HexColor(c)
    dw.add(bc)
    return dw


def _fmt_filters(filters: dict) -> str:
    """Human-readable 'field: value' list of the filters actually applied."""
    parts = [f"{k}: {v}" for k, v in (filters or {}).items() if v not in (None, "")]
    return "; ".join(parts) if parts else "none (all records)"


# --- builders (return a dataset) --------------------------------------------
def build_device_inventory(status=None, date_from=None, date_to=None) -> dict:
    rows = []
    for d in repos.query_devices(status=status):
        # Optional date range on last_seen (report scope).
        if date_from and str(d.get("last_seen")) < str(date_from):
            continue
        if date_to and str(d.get("last_seen")) > str(date_to) + " 23:59:59":
            continue
        rows.append([d["mac_address"], d.get("device_label") or "",
                     d.get("last_ip") or "", d.get("vendor") or "",
                     d.get("os_guess") or "", repos.status_label(d["status"]),
                     "online" if d["is_online"] else "offline",
                     d.get("first_seen"), d.get("last_seen")])
    # Chart 8.2 — device status distribution (matches the on-screen 3.1 accent).
    status_counts = {repos.status_label(s): 0 for s in STATUS_ORDER}
    for r in rows:
        if r[5] in status_counts:
            status_counts[r[5]] += 1
    return {
        "title": "Device Inventory",
        "headers": ["MAC", "Label", "Last IP", "Vendor", "OS", "Status",
                    "Presence", "First seen", "Last seen"],
        "rows": rows,
        "filters": {"status": status, "from": date_from, "to": date_to},
        "chart": {"title": "Devices by status",
                  "labels": [repos.status_label(s) for s in STATUS_ORDER],
                  "data": [status_counts[repos.status_label(s)] for s in STATUS_ORDER],
                  "colors": [ACCENT_HEX] * len(STATUS_ORDER)},
    }


def build_access_history(device_id=None, date_from=None, date_to=None) -> dict:
    if device_id:
        device = repos.get_device(device_id)
        mac = device["mac_address"] if device else str(device_id)
        label = (device.get("device_label") if device else "") or ""
        rows = [[r["seen_at"], mac, label, r["event"], r.get("ip_address") or ""]
                for r in repos.get_device_history(device_id, date_from, date_to,
                                                  limit=_MAX_ROWS)]
    else:
        rows = [[a["seen_at"], a.get("mac_address") or "",
                 a.get("device_label") or "", a["event"], a.get("ip_address") or ""]
                for a in repos.get_activity_feed(limit=_MAX_ROWS,
                                                 date_from=date_from, date_to=date_to)]
    return {
        "title": "Access History",
        "headers": ["Time", "MAC", "Label", "Event", "IP"],
        "rows": rows,
        "filters": {"device_id": device_id, "from": date_from, "to": date_to},
    }


def build_alert_summary(date_from=None, date_to=None, severity=None) -> dict:
    # Friendly rule name (e.g. "Gateway impersonation") — matches the on-screen
    # Alerts table / alert detail page / "by rule" chart, not the raw rule_code.
    rows = [[a["created_at"], a["severity"], repos.rule_label(a["rule_code"]), a["title"],
             a.get("mac_address") or "", a["status"]]
            for a in repos.get_alerts(severity=severity, date_from=date_from,
                                      date_to=date_to, limit=_MAX_ROWS)]
    # Chart 8.1 — alert severity distribution (matches the on-screen 6.1 colours).
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        if r[1] in sev_counts:
            sev_counts[r[1]] += 1
    return {
        "title": "Alert Summary",
        "headers": ["Created", "Severity", "Rule", "Title", "Device MAC", "Status"],
        "rows": rows,
        "filters": {"severity": severity, "from": date_from, "to": date_to},
        "chart": {"title": "Alerts by severity",
                  "labels": list(SEVERITY_ORDER),
                  "data": [sev_counts[s] for s in SEVERITY_ORDER],
                  "colors": [SEV_HEX[s] for s in SEVERITY_ORDER]},
    }


# kind -> builder. REPORT_META drives the report-selection page.
BUILDERS = {
    "devices": build_device_inventory,
    "access": build_access_history,
    "alerts": build_alert_summary,
}
REPORT_META = [("devices", "Device Inventory"),
               ("access", "Access History"),
               ("alerts", "Alert Summary")]


def _build(kind: str, filters: dict) -> dict:
    filters = filters or {}
    if kind == "devices":
        return build_device_inventory(filters.get("status"),
                                      filters.get("date_from"), filters.get("date_to"))
    if kind == "access":
        return build_access_history(filters.get("device_id"),
                                    filters.get("date_from"), filters.get("date_to"))
    if kind == "alerts":
        return build_alert_summary(filters.get("date_from"),
                                   filters.get("date_to"), filters.get("severity"))
    raise KeyError(kind)


# --- renderers ---------------------------------------------------------------
def render_csv(dataset: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(dataset["headers"])
    for r in dataset["rows"]:
        writer.writerow(["" if c is None else c for c in r])
    return buf.getvalue().encode("utf-8-sig")   # BOM => Excel opens UTF-8 cleanly


def render_pdf(dataset: dict, generated_by: str = "-") -> bytes:
    """Render the dataset to a PDF whose header is SELF-DOCUMENTING: title,
    generated-at, generated-by, filter criteria, and the row count."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            title=f"PWNM - {dataset['title']}",
                            leftMargin=1.2 * cm, rightMargin=1.2 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm)
    styles = getSampleStyleSheet()
    elems = [
        Paragraph(f"PWNM - {dataset['title']}", styles["Title"]),
        Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}", styles["Normal"]),
        Paragraph(f"Generated by: {generated_by}", styles["Normal"]),
        Paragraph(f"Filters: {_fmt_filters(dataset.get('filters'))}", styles["Normal"]),
        Paragraph(f"Rows: {len(dataset['rows'])}", styles["Normal"]),
        Spacer(1, 0.4 * cm),
    ]
    # Embedded distribution chart (alert-severity / device-status), if any.
    chart = dataset.get("chart")
    if chart and sum(chart["data"]) > 0:
        elems.append(Paragraph(chart["title"], styles["Heading4"]))
        elems.append(_bar_drawing(chart["labels"], chart["data"], chart["colors"]))
        elems.append(Spacer(1, 0.4 * cm))

    data = [dataset["headers"]] + [["" if c is None else str(c) for c in r]
                                   for r in dataset["rows"]]
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f2f2f2")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(table)
    doc.build(elems)
    return buf.getvalue()


def download_report(kind: str, fmt: str, filters: dict | None = None,
                    generated_by: str = "-") -> tuple[bytes, str]:
    """Build report `kind` with `filters` and render it as `fmt` (csv|pdf).
    Returns (data, mimetype)."""
    if kind not in BUILDERS:
        raise KeyError(kind)
    dataset = _build(kind, filters or {})
    if fmt == "csv":
        return render_csv(dataset), CSV_MIME
    if fmt == "pdf":
        return render_pdf(dataset, generated_by), PDF_MIME
    raise ValueError(fmt)
