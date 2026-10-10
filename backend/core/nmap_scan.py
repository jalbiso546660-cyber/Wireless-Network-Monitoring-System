"""
core/nmap_scan.py
=================
Optional deep device profiling with Nmap (Module 2.4 Device Enrichment).

nmap_profile(ip) returns {'ports': [int, ...], 'os_guess': str} — the open TCP
ports and a best-guess operating system for one host. It is DELIBERATELY run on
a slower, bounded schedule (see scheduler.profile_devices), never inside the
fast ARP discovery loop, because an Nmap service+OS scan is expensive.

SAFETY / PORTABILITY:
  * This is standard service discovery against hosts on YOUR OWN network — it
    sends no deauth and does no blocking (project constraint).
  * OS detection (-O) needs Administrator/raw sockets; where that's unavailable
    we retry WITHOUT -O so port discovery still works.
  * If the Nmap program or python-nmap isn't present, nmap_profile returns an
    empty profile and logs once — it never raises, so the scan loop is safe.

Flask-free (core layer).
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# python-nmap is a thin wrapper over the nmap binary. Importing it does not need
# the binary; PortScanner() does — so we guard both.
try:
    import nmap  # python-nmap
    _AVAILABLE = True
except Exception as _e:  # pragma: no cover - import failure
    log.warning("python-nmap unavailable (%s); OS/port profiling disabled.", _e)
    nmap = None  # type: ignore
    _AVAILABLE = False

# -sV service/version, -O OS detection, -T4 faster timing, --top-ports 100 keeps
# the scan bounded, --host-timeout caps a single host so one slow box can't stall
# the profiler.
_ARGS_WITH_OS = "-sV -O -T4 --top-ports 100 --host-timeout 90s"
_ARGS_NO_OS = "-sV -T4 --top-ports 100 --host-timeout 90s"


def _run(ip: str, arguments: str):
    """Return a scanned PortScanner for `ip`, or None on any failure."""
    try:
        scanner = nmap.PortScanner()
    except Exception as e:                       # nmap.exe not found / not runnable
        log.warning("Nmap not usable (%s); profiling disabled.", e)
        return None
    try:
        scanner.scan(hosts=ip, arguments=arguments)
        return scanner
    except Exception as e:                        # e.g. -O needs admin
        log.info("Nmap scan of %s with '%s' failed: %s", ip, arguments, e)
        return None


def _extract(scanner, ip: str) -> dict:
    try:
        if ip not in scanner.all_hosts():
            return {"ports": [], "os_guess": ""}
        host = scanner[ip]
        tcp = host.get("tcp", {}) or {}
        ports = sorted(p for p, info in tcp.items() if info.get("state") == "open")
        osmatch = host.get("osmatch", []) or []
        os_guess = osmatch[0].get("name", "") if osmatch else ""
        return {"ports": list(ports), "os_guess": os_guess}
    except Exception as e:                         # defensive: never let parsing crash
        log.info("Nmap result parse for %s failed: %s", ip, e)
        return {"ports": [], "os_guess": ""}


def nmap_profile(ip: str) -> dict:
    """Open TCP ports + OS estimate for one host. Never raises; empty on any
    problem (missing tool, no privilege, host unreachable)."""
    if not _AVAILABLE or not ip:
        return {"ports": [], "os_guess": ""}
    # Prefer the OS-detection scan; fall back to a no-OS scan without privilege.
    scanner = _run(ip, _ARGS_WITH_OS) or _run(ip, _ARGS_NO_OS)
    if scanner is None:
        return {"ports": [], "os_guess": ""}
    return _extract(scanner, ip)
