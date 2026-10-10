"""
web/routes/charts.py  — JSON endpoints for the Chart.js visualizations.

Each endpoint returns JSON in the exact shape charts.js expects. Aggregation is
done in SQL (see data/repos.py); the routes only gap-fill / zero-fill for
presentation. All endpoints are read-only and require a logged-in user (any
role may view the dashboards).
"""
from __future__ import annotations

from collections import OrderedDict, defaultdict
from datetime import datetime, time as dtime, timedelta

from flask import Blueprint, jsonify, request
from flask_login import login_required

from data import repos

charts_bp = Blueprint("charts", __name__, url_prefix="/api/charts")

SEVERITY_ORDER = ("low", "medium", "high", "critical")
STATUS_ORDER = ("authorized", "unauthorized", "blocked")
# All eight detection rules — Chart 6.3 shows every one, including zero-count.
RULE_CODES = ("UNAUTH_NEW", "UNAUTH_RETURN", "BLOCKED_SEEN", "ARP_SPOOF",
              "PORT_SCAN", "OFF_HOURS_JOIN", "IP_CHURN", "SERVICE_ANOMALY")


_MAX_RANGE_DAYS = 366          # cap custom ranges (keeps axes and queries bounded)
_HOURLY_MAX_DAYS = 2           # ranges up to this long plot hourly, longer ones daily


def _date_range():
    """Parse optional ?from=YYYY-MM-DD&to=YYYY-MM-DD into a [start, end) window.

    Returns None when no range was requested, so each chart keeps its original
    rolling default. Invalid dates are ignored (default window); a reversed
    range is swapped; spans are capped at _MAX_RANGE_DAYS. `end` is exclusive
    (midnight after the `to` day), so from=to=today means the whole of today."""
    f_raw, t_raw = request.args.get("from"), request.args.get("to")
    if not f_raw and not t_raw:
        return None
    try:
        d_from = datetime.strptime(f_raw, "%Y-%m-%d").date() if f_raw else None
        d_to = datetime.strptime(t_raw, "%Y-%m-%d").date() if t_raw else None
    except ValueError:
        return None
    today = datetime.now().date()
    d_from = d_from or d_to or today
    d_to = d_to or today
    if d_from > d_to:
        d_from, d_to = d_to, d_from
    if (d_to - d_from).days + 1 > _MAX_RANGE_DAYS:
        d_from = d_to - timedelta(days=_MAX_RANGE_DAYS - 1)
    start = datetime.combine(d_from, dtime.min)
    end = datetime.combine(d_to + timedelta(days=1), dtime.min)
    return {"start": start, "end": end, "from": d_from, "to": d_to,
            "days": (d_to - d_from).days + 1}


def _axis(rng):
    """Contiguous bucket axis for a window: hourly for short ranges, daily for
    long ones. Returns (granularity, [(key, label, bucket_start), ...])."""
    if rng["days"] <= _HOURLY_MAX_DAYS:
        now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        last = min(rng["end"] - timedelta(hours=1), now_hour)   # no future hours
        pts, t = [], rng["start"]
        multi_day = rng["days"] > 1
        while t <= last:
            pts.append((t.strftime("%Y-%m-%d %H:00"),
                        t.strftime("%m-%d %H:00" if multi_day else "%H:00"), t))
            t += timedelta(hours=1)
        return "hour", pts
    last_day = min(rng["to"], datetime.now().date())
    pts, d = [], rng["from"]
    while d <= last_day:
        pts.append((d.strftime("%Y-%m-%d"), d.strftime("%m-%d"),
                    datetime.combine(d, dtime.min)))
        d += timedelta(days=1)
    return "day", pts


def _range_meta(rng):
    return None if rng is None else {"from": rng["from"].isoformat(),
                                     "to": rng["to"].isoformat()}


def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    v = request.args.get(name, default, type=int) or default
    return max(lo, min(hi, v))


# --- Chart 4.2 / 7.1 — occupancy over time ----------------------------------
@charts_bp.route("/occupancy")
@login_required
def occupancy():
    q_start = str(repos.get_setting("quiet_hours_start", "00:00"))
    q_end = str(repos.get_setting("quiet_hours_end", "05:00"))
    rng = _date_range()

    if rng is None:                                   # default: rolling last N hours
        hours = _int_arg("hours", 24, 1, 168)
        rows = {r["bucket"]: r["count"] for r in repos.chart_occupancy(hours)}
        # Build a contiguous hourly axis so gaps read as zero, not as missing points.
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        pts = [((start + timedelta(hours=i)).strftime("%Y-%m-%d %H:00"),
                (start + timedelta(hours=i)).strftime("%H:00"),
                start + timedelta(hours=i)) for i in range(hours)]
        gran = "hour"
    else:
        gran, pts = _axis(rng)
        rows = {r["bucket"]: r["count"] for r in
                repos.chart_occupancy(start=rng["start"], end=rng["end"], bucket=gran)}

    labels = [label for _k, label, _t in pts]
    data = [int(rows.get(key, 0)) for key, _l, _t in pts]
    # Quiet-hours shading only makes sense on an hourly axis.
    quiet = [gran == "hour" and _in_quiet_hours(t.strftime("%H:%M"), q_start, q_end)
             for _k, _l, t in pts]
    return jsonify({"labels": labels, "data": data, "quiet": quiet,
                    "granularity": gran, "range": _range_meta(rng),
                    "quiet_hours": {"start": q_start, "end": q_end}})


def _in_quiet_hours(hhmm: str, start: str, end: str) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hhmm < end
    return hhmm >= start or hhmm < end            # wraps midnight


# --- Chart 6.1 / 7.2 — alerts by severity -----------------------------------
@charts_bp.route("/alerts-by-severity")
@login_required
def alerts_by_severity():
    open_only = request.args.get("open") in ("1", "true", "yes")
    rng = _date_range()
    if rng is None:
        counts = repos.chart_alerts_severity_counts(_int_arg("days", 7, 1, 365),
                                                    open_only=open_only)
    else:
        counts = repos.chart_alerts_severity_counts(open_only=open_only,
                                                    start=rng["start"], end=rng["end"])
    # Fixed order low->critical, zero-filled — the order carries meaning.
    return jsonify({
        "labels": list(SEVERITY_ORDER),
        "data": [counts.get(s, 0) for s in SEVERITY_ORDER],
        "range": _range_meta(rng),
    })


# --- Chart 6.2 — alerts over time (one line per severity) -------------------
@charts_bp.route("/alerts-over-time")
@login_required
def alerts_over_time():
    rng = _date_range()
    piv = defaultdict(lambda: defaultdict(int))
    if rng is None:
        days = _int_arg("days", 30, 1, 365)
        rows = repos.chart_alerts_over_time(days)
        today = datetime.now().date()
        axis = [today - timedelta(days=days - 1 - i) for i in range(days)]
    else:
        rows = repos.chart_alerts_over_time(start=rng["start"], end=rng["end"])
        last_day = min(rng["to"], datetime.now().date())
        axis, d = [], rng["from"]
        while d <= last_day:
            axis.append(d)
            d += timedelta(days=1)
        axis = axis or [rng["from"]]
    for r in rows:
        piv[str(r["d"])][r["severity"]] += int(r["c"])
    return jsonify({
        "labels": [d.strftime("%m-%d") for d in axis],
        # One series per severity, fixed order, zero-filled — 2+ series so the
        # chart carries a legend.
        "series": [{"severity": s, "data": [piv[str(d)].get(s, 0) for d in axis]}
                   for s in SEVERITY_ORDER],
        "range": _range_meta(rng),
    })


# --- Chart 6.3 — alerts by rule (all eight, zeros included) ------------------
@charts_bp.route("/alerts-by-rule")
@login_required
def alerts_by_rule():
    rng = _date_range()
    if rng is None:
        counts = repos.chart_alerts_by_rule(_int_arg("days", 30, 1, 365))
    else:
        counts = repos.chart_alerts_by_rule(start=rng["start"], end=rng["end"])
    pairs = sorted(((code, counts.get(code, 0)) for code in RULE_CODES),
                   key=lambda p: p[1], reverse=True)      # descending, zeros last
    return jsonify({"labels": [repos.rule_label(c) for c, _ in pairs],
                    "data": [n for _, n in pairs], "range": _range_meta(rng)})


# --- Chart 3.1 — devices by status (fixed order) ----------------------------
@charts_bp.route("/device-status")
@login_required
def device_status():
    rng = _date_range()
    counts = (repos.chart_device_status() if rng is None else
              repos.chart_device_status(start=rng["start"], end=rng["end"]))
    return jsonify({"labels": [repos.status_label(s) for s in STATUS_ORDER],
                    "data": [counts.get(s, 0) for s in STATUS_ORDER],
                    "range": _range_meta(rng)})


# --- Chart 3.2 — top vendors, tail folded into "Other" ----------------------
@charts_bp.route("/vendor-distribution")
@login_required
def vendor_distribution():
    limit = _int_arg("limit", 8, 1, 20)
    rng = _date_range()
    rows = (repos.chart_vendor_counts() if rng is None else
            repos.chart_vendor_counts(start=rng["start"], end=rng["end"]))
    labels = [r["vendor"] for r in rows[:limit]]
    data = [int(r["count"]) for r in rows[:limit]]
    other = sum(int(r["count"]) for r in rows[limit:])
    if other:
        labels.append("Other")               # never a 9th colour — fold the tail
        data.append(other)
    return jsonify({"labels": labels, "data": data, "range": _range_meta(rng)})


# --- Chart 2.1 — devices found per scan -------------------------------------
@charts_bp.route("/scan-history")
@login_required
def scan_history():
    rng = _date_range()
    if rng is None:
        hours = _int_arg("hours", 24, 1, 168)
        buckets = {r["bucket"]: float(r["avg_found"]) for r in repos.chart_scan_history(hours)}
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        pts = [((start + timedelta(hours=i)).strftime("%Y-%m-%d %H:00"),
                (start + timedelta(hours=i)).strftime("%H:00"), None) for i in range(hours)]
    else:
        gran, pts = _axis(rng)
        buckets = {r["bucket"]: float(r["avg_found"]) for r in
                   repos.chart_scan_history(start=rng["start"], end=rng["end"], bucket=gran)}
    if not buckets:
        return jsonify({"labels": [], "data": [], "range": _range_meta(rng)})  # empty state

    # Contiguous axis; a bucket with no scans reads as 0 (visible outage).
    return jsonify({"labels": [label for _k, label, _t in pts],
                    "data": [round(buckets.get(key, 0.0), 1) for key, _l, _t in pts],
                    "range": _range_meta(rng)})


# ===========================================================================
# Chart 4.1 — device presence timeline (floating horizontal bars)
#
# THE TRANSFORM (access_logs rows -> [start, end] bars), walked step by step:
#   * Fetch every access_logs row for the chosen day, ordered per device by time.
#   * For each device we sweep its events, holding an OPEN segment:
#       - 'joined'  opens a segment (start = its time) if none is open;
#       - 'present' also opens one if none is open (the device was already online
#         when we first saw it today), and always extends the "last seen" marker;
#       - 'left'    CLOSES the open segment -> emit a bar [start, left-time].
#   * A segment still open after the last event = the device never left within the
#     day. If the day is today and the device is currently online, the bar runs to
#     NOW; otherwise it runs to the last time we saw it.
#   * Times are expressed as MINUTES SINCE MIDNIGHT (0..1440) so a plain linear
#     x-axis can render them; the tick callback formats them back to HH:00.
# ===========================================================================
def _minutes(ts, day_start) -> float:
    return max(0.0, min(1440.0, (ts - day_start).total_seconds() / 60.0))


def _emit_bar(bars, name, start, end, ip, day_start, online):
    s, e = _minutes(start, day_start), _minutes(end, day_start)
    if e <= s:
        e = min(1440.0, s + 1.0)            # keep a still-brief visit visible
    total = int(round(e - s))
    bars.append({
        "y": name, "x": [round(s, 1), round(e, 1)],
        "join": start.strftime("%H:%M"),
        "leave": "online" if online else end.strftime("%H:%M"),
        "dur": f"{total // 60}h {total % 60}m",
        "ip": ip or "",
    })


def _coalesce_gap_seconds() -> float:
    """Gaps shorter than this are scan jitter (a device briefly missing a scan),
    not a real departure, so we merge the sessions around them. Derived from the
    reconciliation thresholds: a device is only marked 'left' after
    offline_after_missed scans, so anything up to ~that long is a flap."""
    try:
        interval = repos.get_int_setting("scan_interval_seconds", 60)
        missed = repos.get_int_setting("offline_after_missed", 3)
        return max(180, (missed + 1) * interval)      # at least 3 minutes
    except Exception:
        return 300


def _build_presence(rows, day_start, day_end, now, is_today):
    by_dev = OrderedDict()
    for r in rows:
        by_dev.setdefault(r["device_id"], []).append(r)

    gap = _coalesce_gap_seconds()
    labels, used, bars = [], set(), []
    span_lo = span_hi = None
    for evs in by_dev.values():
        base = (evs[0]["device_label"] or evs[0]["hostname"]
                or evs[0]["mac_address"])
        name = base if base not in used else f"{base} ({evs[0]['mac_address'][-8:]})"
        used.add(name)
        labels.append(name)

        # 1) pair events into raw [start, end, online, ip] sessions.
        raw = []
        seg_start = last_seen = last_ip = None
        for e in evs:
            ts, ev = e["seen_at"], e["event"]
            if ev in ("joined", "present"):
                if seg_start is None:
                    seg_start = ts
                last_seen = ts
                if e["ip_address"]:
                    last_ip = e["ip_address"]
            elif ev == "left" and seg_start is not None:
                raw.append([seg_start, ts, False, last_ip])
                seg_start = last_seen = last_ip = None
        if seg_start is not None:
            still_online = is_today and bool(evs[-1]["is_online"])
            end = min(now if still_online else (last_seen or seg_start), day_end)
            raw.append([seg_start, end, still_online, last_ip])

        # 2) coalesce sessions separated by less than a flap's worth of time.
        merged = []
        for s in raw:
            if merged and (s[0] - merged[-1][1]).total_seconds() <= gap:
                merged[-1][1] = s[1]                  # extend to this session's end
                merged[-1][2] = s[2]                  # carry the later online flag
                merged[-1][3] = s[3] or merged[-1][3]
            else:
                merged.append(list(s))

        # 3) emit bars and track the overall active window (for the x-axis).
        for st, en, online, ip in merged:
            _emit_bar(bars, name, st, en, ip, day_start, online)
            lo, hi = _minutes(st, day_start), _minutes(en, day_start)
            span_lo = lo if span_lo is None else min(span_lo, lo)
            span_hi = hi if span_hi is None else max(span_hi, hi)

    # Fit the axis to the active window (rounded out to whole hours), instead of
    # always drawing an empty 00:00–24:00 when only part of the day has data.
    if span_lo is None:
        x_min, x_max = 0, 1440
    else:
        x_min = max(0, int(span_lo // 60) * 60)
        x_max = min(1440, (int(span_hi // 60) + 1) * 60)
        if x_max - x_min < 60:                        # keep at least a 1-hour window
            x_max = min(1440, x_min + 60)
    return labels, bars, x_min, x_max


@charts_bp.route("/presence-timeline")
@login_required
def presence_timeline():
    date_str = request.args.get("date")
    try:
        day = (datetime.strptime(date_str, "%Y-%m-%d").date()
               if date_str else datetime.now().date())
    except ValueError:
        day = datetime.now().date()
    day_start = datetime.combine(day, dtime.min)
    day_end = day_start + timedelta(days=1)
    now = datetime.now()
    rows = repos.chart_presence_events(day_start, day_end)
    labels, bars, x_min, x_max = _build_presence(rows, day_start, day_end, now,
                                                 day == now.date())
    return jsonify({"labels": labels, "bars": bars,
                    "x_min": x_min, "x_max": x_max, "date": day.isoformat()})
