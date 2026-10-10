"""
scheduler.py
============
APScheduler background scan loop (Phase 5).

One interval job runs discover -> persist. It is engineered against the three
failure modes the brief calls out:

  * NO OVERLAP: the job is registered with max_instances=1 and coalesce=True,
    AND a module-level lock serialises the actual work, so a manual scan can
    never run concurrently with the interval scan.
  * SURVIVES ERRORS: run_scan_cycle() catches everything — one bad cycle (e.g.
    Wi-Fi briefly down) logs and returns; the scheduler keeps ticking.
  * NO DOUBLE START under Flask's reloader: app.py only calls start_scheduler()
    in the process that actually serves requests (see its __main__ guard).

LAYERING: this module (not the web layer) imports the Scapy-based scanner. The
web routes trigger a manual scan via request_immediate_scan(), which only
enqueues a job — the sweep runs here, in the scheduler thread, never in a
request. The interface/subnet to monitor is stored in the settings table
(auto-derived on first run) so the headless job knows what to scan.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from core import interfaces, nmap_scan, scanner, sniffer
from data import repos
from detection import engine

log = logging.getLogger(__name__)

SCAN_JOB_ID = "scan_cycle"
PROFILE_JOB_ID = "profile_devices"
PRUNE_JOB_ID = "prune_old_records"
PROFILE_MAX_HOSTS = 3              # bound the slow nmap profiler per pass
PRUNE_INTERVAL_SECONDS = 86400    # run data-retention pruning once a day
_scheduler: BackgroundScheduler | None = None
_start_lock = threading.Lock()
_cycle_lock = threading.Lock()     # guarantees scans never overlap
_profile_lock = threading.Lock()   # serialises the nmap profiler
_prune_lock = threading.Lock()     # serialises the retention prune
_sniffer_state: sniffer.SnifferState | None = None   # ARP table + SYN window


def get_monitor_target() -> tuple[str | None, str | None]:
    """Return (interface, subnet) to scan. Read from settings; if unset,
    auto-derive the best real adapter and persist it so it's visible/editable
    on the settings page."""
    subnet = repos.get_setting("monitor_subnet")
    iface = repos.get_setting("monitor_interface")
    if not subnet:
        ifaces = interfaces.list_interfaces()
        chosen = next((i for i in ifaces if i["is_up"] and not i["is_virtual"]),
                      ifaces[0] if ifaces else None)
        if chosen:
            iface, subnet = chosen["name"], chosen["subnet_cidr"]
            repos.set_setting("monitor_subnet", subnet)
            repos.set_setting("monitor_interface", iface)
            log.info("Auto-selected monitor target: %s on %s", subnet, iface)
    return iface, subnet


def run_scan_cycle(iface: str | None = None, subnet: str | None = None,
                   trigger: str = "scheduler", user_id: int | None = None) -> None:
    """Module 2.5 orchestration: open session -> discover -> enrich -> persist
    -> detect -> close. NEVER raises (protects the scheduler).

    iface/subnet default to the configured monitor target, so the headless job
    can call this with no arguments and still know what to scan.
    """
    if not _cycle_lock.acquire(blocking=False):
        log.info("A scan is already running; skipping this %s trigger.", trigger)
        return
    try:
        if not subnet:
            iface, subnet = get_monitor_target()
        if not subnet:
            log.warning("No usable interface to monitor; skipping scan cycle.")
            return
        # Discovery (+ enrichment inside discover): Scapy ARP sweep first, with a
        # no-Npcap `arp -a` fallback so the loop still works without admin.
        #
        # PERFORMANCE NOTE: a full-subnet ARP sweep (arp_sweep in core/scanner.py)
        # is the expensive part of this cycle — on Windows/Npcap, sending one ARP
        # request per host across a /24 (254 addresses) measured ~24-30s, almost
        # entirely in packet injection, not the reply-collection wait (confirmed
        # by testing: halving the collection timeout changed nothing). This is
        # invisible in scan_sessions.started_at/finished_at, which are only set
        # AFTER discovery completes. See arp_sweep()'s retry=0 (was 1): Scapy's
        # retry resends every UNANSWERED packet and waits the full timeout again,
        # which roughly doubled sweep time for a sparse /24 (~2-3 live hosts out
        # of 254) where almost every packet goes unanswered on the first pass.
        try:
            devices = scanner.discover(iface, subnet, use_fallback=False)
        except scanner.NpcapUnavailable as e:
            log.warning("Scapy sweep unavailable (%s); using arp -a fallback.", e)
            scanner.prime_arp_cache(subnet)
            devices = scanner.discover(iface, subnet, use_fallback=True)
        summary = repos.persist_scan(devices, subnet, iface,
                                     triggered_by=trigger, user_id=user_id)
        log.info("[%s] scan #%s: found=%d joined=%d left=%d",
                 trigger, summary["scan_id"], summary["devices_found"],
                 len(summary["joined"]), len(summary["left"]))

        # Run the detection engine on this scan (never fatal to the loop).
        try:
            gateway = interfaces.get_default_gateway()
        except Exception:
            gateway = None
        engine.evaluate(summary, sniffer_state=_sniffer_state, gateway=gateway)
    except Exception:
        # Swallow EVERYTHING so a single bad cycle can't kill the loop.
        log.exception("run_scan_cycle failed; scheduler stays alive")
    finally:
        _cycle_lock.release()
        _maybe_reschedule()


def prune_old_records() -> None:
    """Data-retention job: delete access_logs and finished scans older than
    log_retention_days. NEVER raises; bounds unbounded history growth."""
    if not _prune_lock.acquire(blocking=False):
        return
    try:
        days = repos.get_int_setting("log_retention_days", 90)
        removed = repos.prune_old_records(days)
        if removed["access_logs"] or removed["scan_sessions"]:
            log.info("Retention prune (>%dd): removed %d access_logs, %d scans.",
                     days, removed["access_logs"], removed["scan_sessions"])
    except Exception:
        log.exception("prune_old_records failed; scheduler stays alive")
    finally:
        _prune_lock.release()


def profile_devices() -> None:
    """Module 2.4 (slow schedule): nmap-profile a few not-yet-profiled online
    devices, storing open ports + OS estimate. NEVER raises; a no-op where nmap
    is unavailable. Kept OFF the fast scan path because nmap is expensive."""
    if not _profile_lock.acquire(blocking=False):
        return
    try:
        for dev in repos.devices_needing_profile(PROFILE_MAX_HOSTS):
            ip = dev.get("last_ip")
            if not ip:
                continue
            profile = nmap_scan.nmap_profile(ip)
            repos.set_device_profile(dev["id"], profile.get("os_guess", ""),
                                     profile.get("ports", []))
            if profile.get("ports"):
                log.info("Profiled %s: ports=%s os=%s", ip,
                         profile["ports"], profile.get("os_guess") or "?")
    except Exception:
        log.exception("profile_devices failed; scheduler stays alive")
    finally:
        _profile_lock.release()


def apply_scan_interval(seconds: int) -> bool:
    """Reschedule the running scan job to a new interval WITHOUT restarting the
    app (Module 9.4). Returns True if a live job was rescheduled, False if the
    scheduler isn't running. Exposed on app.config['APPLY_SCAN_INTERVAL'] so the
    settings route can call it without importing the scheduler/Scapy graph."""
    if _scheduler is None:
        return False
    _scheduler.reschedule_job(SCAN_JOB_ID, trigger="interval", seconds=int(seconds))
    log.info("Scan interval rescheduled to every %ds (live).", int(seconds))
    return True


def _maybe_reschedule() -> None:
    """Live-tune fallback: if scan_interval_seconds changed in the DB but was not
    applied immediately, pick it up at the end of a cycle."""
    if _scheduler is None:
        return
    try:
        desired = repos.get_int_setting("scan_interval_seconds", 60)
        job = _scheduler.get_job(SCAN_JOB_ID)
        if job is not None and int(job.trigger.interval.total_seconds()) != int(desired):
            apply_scan_interval(desired)
    except Exception:
        log.exception("interval reschedule check failed")


def start_scheduler(app=None) -> BackgroundScheduler:
    """Start the background scheduler once (idempotent). Stores the manual-scan
    trigger on app.config so web routes can enqueue a scan without importing
    Scapy."""
    global _scheduler, _sniffer_state
    with _start_lock:
        if _sniffer_state is None:
            # Best-effort live traffic capture (ARP + TCP SYN); dormant if Npcap
            # is missing so the traffic rules just stay quiet.
            _sniffer_state = sniffer.SnifferState()
            sniffer.start_sniffer(_sniffer_state,
                                  iface=repos.get_setting("monitor_interface"))
        if _scheduler is None:
            interval = repos.get_int_setting("scan_interval_seconds", 60)
            profile_interval = repos.get_int_setting("profile_interval_seconds", 300)
            sched = BackgroundScheduler(daemon=True)
            sched.add_job(
                run_scan_cycle, trigger="interval", seconds=interval, id=SCAN_JOB_ID,
                max_instances=1,          # APScheduler won't launch an overlapping run
                coalesce=True,            # missed runs collapse into one
                misfire_grace_time=30,
                next_run_time=datetime.now(),   # first scan immediately at boot
            )
            # Slower, separate job for the expensive nmap profiling (Module 2.4).
            sched.add_job(
                profile_devices, trigger="interval", seconds=profile_interval,
                id=PROFILE_JOB_ID, max_instances=1, coalesce=True,
                misfire_grace_time=60,
            )
            # Daily data-retention prune (bounds unbounded history growth).
            sched.add_job(
                prune_old_records, trigger="interval", seconds=PRUNE_INTERVAL_SECONDS,
                id=PRUNE_JOB_ID, max_instances=1, coalesce=True, misfire_grace_time=300,
            )
            sched.start()
            _scheduler = sched
            log.info("Scheduler started; scanning every %ds, profiling every %ds.",
                     interval, profile_interval)
        if app is not None:
            app.config["SCHEDULER"] = _scheduler
            app.config["SCAN_TRIGGER"] = request_immediate_scan
            app.config["APPLY_SCAN_INTERVAL"] = apply_scan_interval
            app.config["SNIFFER_STATE"] = _sniffer_state   # live capture state (System Health)
        return _scheduler


def request_immediate_scan(user_id: int | None = None) -> bool:
    """Enqueue a one-off scan to run NOW (used by POST /scan/now). Returns
    immediately; the sweep runs in the scheduler thread. False if no scheduler."""
    if _scheduler is None:
        return False
    _scheduler.add_job(
        run_scan_cycle, kwargs={"trigger": "manual", "user_id": user_id},
        id="manual_scan", replace_existing=True, next_run_time=datetime.now(),
        max_instances=1, coalesce=True, misfire_grace_time=30)
    return True


def shutdown_scheduler() -> None:
    global _scheduler
    sniffer.stop_sniffer()          # stop the capture thread cleanly
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
