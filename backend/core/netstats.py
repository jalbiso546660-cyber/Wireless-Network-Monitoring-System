"""
core/netstats.py
================
Live network throughput + latency for the dashboard (psutil + a subprocess
ping — NO Flask, NO Scapy, so the web layer can import it the same way it
imports core.interfaces).

WHAT IT MEASURES
  * download / upload  — the host NIC's current throughput in bytes/sec,
    computed from the delta of psutil.net_io_counters() between samples. This is
    live interface activity, NOT a saturating speed-test.
  * ping               — round-trip time (ms), reported as the MEDIAN of the
    last few ICMP echoes so one spike or timeout does not swing the reading.
    Target is the default gateway (true local Wi-Fi latency); many gateways
    drop ICMP, in which case it falls back to a public resolver and the value
    is INTERNET latency instead — `ping_target` says which was used, and
    `ping_loss` is the percentage of recent echoes that got no reply.

HOW IT STAYS OFF THE REQUEST PATH
  A single daemon thread samples on a fixed cadence and caches the result, so
  the polled endpoint just reads the cache and never blocks on the (potentially
  slow) ping subprocess. The thread starts lazily on the first snapshot() call.
"""
from __future__ import annotations

import re
import statistics
import subprocess
import sys
import threading
import time
from collections import deque

import psutil

from core import interfaces

_SAMPLE_INTERVAL = 2.0          # seconds between background samples
_PING_TIMEOUT_MS = 1000
_GW_REFRESH_EVERY = 30.0        # re-detect the gateway at most this often
# Many gateways/routers drop ICMP echo; fall back to a public anycast resolver
# so "Ping" reflects real connectivity latency instead of always showing "—".
_PING_FALLBACK = "1.1.1.1"      # Cloudflare DNS

# A single ICMP echo is a noisy estimate: real links swing widely packet to
# packet. We keep the last few samples and report their MEDIAN, which ignores
# one-off spikes and timeouts without hiding a genuine change in latency.
_PING_HISTORY = 5

_recent_pings: deque = deque(maxlen=_PING_HISTORY)
_lock = threading.Lock()
_cache = {"up_bps": 0.0, "down_bps": 0.0, "ping_ms": None,
          "ping_sample": None, "ping_loss": 0,
          "ping_target": None, "gateway": None}
_last_io: tuple[float, int, int] | None = None      # (monotonic_t, sent, recv)
_gw_ip: str | None = None
_gw_checked_at: float = 0.0
_started = False


def _human_bps(bps: float) -> str:
    """Human-readable bit-rate (bits, like ISPs quote): 0 b/s, 940 Kb/s, 12.3 Mb/s."""
    bits = max(0.0, bps) * 8
    for unit, factor in (("Gb/s", 1e9), ("Mb/s", 1e6), ("Kb/s", 1e3)):
        if bits >= factor:
            return f"{bits / factor:.1f} {unit}"
    return f"{bits:.0f} b/s"


def _current_gateway() -> str | None:
    """Cache the detected default-gateway IP; refresh occasionally (Wi-Fi roam)."""
    global _gw_ip, _gw_checked_at
    now = time.monotonic()
    if _gw_ip is None or (now - _gw_checked_at) > _GW_REFRESH_EVERY:
        gw = interfaces.get_default_gateway()
        _gw_ip = gw["ip"] if gw else None
        _gw_checked_at = now
    return _gw_ip


def measure_ping(host: str | None, timeout_ms: int = _PING_TIMEOUT_MS) -> int | None:
    """One ICMP echo to `host`; return RTT in whole ms, or None if unreachable.

    Parses the "<n>ms" the OS ping prints. The number+``ms`` token is stable
    across Windows locales (unlike the localized 'time='/'Reply' labels), so we
    match on it directly."""
    if not host:
        return None
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_ms / 1000 + 1).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None
    # Prefer the reply's "time=Xms" / "time<1ms"; fall back to any "<n>ms".
    m = re.search(r"time[=<]\s*(\d+)\s*ms", out, re.IGNORECASE) or \
        re.search(r"(\d+)\s*ms", out)
    return int(m.group(1)) if m else None


def _sample_once() -> None:
    global _last_io
    io = psutil.net_io_counters()
    now = time.monotonic()
    up = down = 0.0
    if _last_io is not None:
        dt = now - _last_io[0]
        if dt > 0:
            up = max(0.0, (io.bytes_sent - _last_io[1]) / dt)
            down = max(0.0, (io.bytes_recv - _last_io[2]) / dt)
    _last_io = (now, io.bytes_sent, io.bytes_recv)

    gw = _current_gateway()
    target = gw
    ping = measure_ping(gw) if gw else None
    if ping is None:                        # gateway blocks ICMP -> use fallback
        fb = measure_ping(_PING_FALLBACK)
        if fb is not None:
            ping, target = fb, _PING_FALLBACK
    # Smooth the reading, and remember whether replies are being lost at all.
    _recent_pings.append(ping)
    got = [v for v in _recent_pings if v is not None]
    smoothed = int(round(statistics.median(got))) if got else None
    loss = round(100 * (len(_recent_pings) - len(got)) / len(_recent_pings))

    with _lock:
        _cache.update(up_bps=up, down_bps=down, ping_ms=smoothed,
                      ping_sample=ping, ping_loss=loss,
                      ping_target=target, gateway=gw)


def _loop() -> None:
    while True:
        try:
            _sample_once()
        except Exception:       # never let a transient error kill the sampler
            pass
        time.sleep(_SAMPLE_INTERVAL)


def _ensure_started() -> None:
    global _started
    if _started:
        return
    _started = True
    _sample_once()              # prime immediately (throughput fills in next tick)
    threading.Thread(target=_loop, name="netstats-sampler", daemon=True).start()


def snapshot() -> dict:
    """Latest cached throughput + ping, with human-readable rate strings.
    Starts the background sampler on first call."""
    _ensure_started()
    with _lock:
        c = dict(_cache)
    c["up_human"] = _human_bps(c["up_bps"])
    c["down_human"] = _human_bps(c["down_bps"])
    return c
