"""
web/routes/reports.py  — Module 8: Reporting

Reports view (all roles): download device inventory, access history, and the
alert summary as CSV or PDF, filterable by date range (and status/severity).
Generation lives in reports/generator.py.
"""
from __future__ import annotations

import io
from datetime import datetime

from flask import (Blueprint, abort, render_template, request, send_file)
from flask_login import current_user, login_required

from reports import generator
from web.routes.auth import role_required

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def index():
    # All roles may VIEW the reports page (Module 8: viewer = view-only).
    return render_template("reports.html", reports=generator.REPORT_META)


@reports_bp.route("/reports/<kind>.<fmt>")
@role_required("monitor")   # generating/exporting is Admin + Monitor only
def download(kind: str, fmt: str):
    if kind not in generator.BUILDERS or fmt not in ("csv", "pdf"):
        abort(404)
    filters = {
        "date_from": request.args.get("from") or None,
        "date_to": request.args.get("to") or None,
        "status": request.args.get("status") or None,
        "severity": request.args.get("severity") or None,
        "device_id": request.args.get("device_id", type=int),
    }
    data, mimetype = generator.download_report(
        kind, fmt, filters, generated_by=current_user.username)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=True,
                     download_name=f"pwnm_{kind}_{stamp}.{fmt}")
