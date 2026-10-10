"""
core/sniffer.py
===============
Traffic Observation for the detection engine (Module 5.1).

Two rolling, bounded, thread-safe stores fed by one background Scapy capture:
  * PortScanTracker  — distinct destination ports each source has SYN-scanned,
    in a sliding window (feeds rule_port_scan).
  * ArpTable         — which MAC(s) have claimed each IP, in a sliding window
    (feeds rule_arp_spoof's "two MACs, one IP" case — the ARP-poisoning tell).
SnifferState bundles both so the engine receives one object.

start_sniffer() runs a Scapy AsyncSniffer with the BPF filter
``arp or (tcp[tcpflags] & tcp-syn != 0)`` — i.e. ARP frames and TCP SYNs only —
and can be STOPPED CLEANLY on shutdown. It is OPTIONAL: if Scapy/Npcap can't
load it logs once and returns None, and the traffic-based rules simply stay
quiet (no false positives). Flask-free (core layer).
"""
from __future__ import annotations

import logging
import threading
import time as _time
from collections import defaultdict, deque

log = logging.getLogger(__name__)


def _norm_mac(raw: str) -> str:
    return (raw or "").replace("-", ":").lower()


class PortScanTracker:
    """Sliding-window record of which destination ports each source touched."""

    def __init__(self) -> None:
        self._obs: dict[str, deque] = defaultdict(deque)   # src -> deque[(ts, port)]
        self._alerted: dict[str, float] = {}               # src -> last alert ts
        self._lock = threading.Lock()

    def observe(self, src_ip: str, dst_port: int, ts: float | None = None) -> None:
        ts = _time.time() if ts is None else ts
        with self._lock:
            self._obs[src_ip].append((ts, int(dst_port)))

    def _prune(self, now: float, window: float) -> None:
        for src in list(self._obs):
            dq = self._obs[src]
            while dq and now - dq[0][0] > window:
                dq.popleft()
            if not dq:
                del self._obs[src]

    def offenders(self, threshold: int, window: float,
                  now: float | None = None,
                  cooldown: float | None = None) -> list[tuple[str, int]]:
        """[(src_ip, distinct_port_count)] for sources at/over `threshold`
        distinct ports within `window`s, excluding sources alerted within
        `cooldown` (defaults to `window`). Returned sources are marked alerted."""
        now = _time.time() if now is None else now
        cooldown = window if cooldown is None else cooldown
        out: list[tuple[str, int]] = []
        with self._lock:
            self._prune(now, window)
            for src, dq in self._obs.items():
                ports = {p for (t, p) in dq if now - t <= window}
                if len(ports) >= threshold:
                    last = self._alerted.get(src)
                    if last is None or now - last >= cooldown:
                        self._alerted[src] = now
                        out.append((src, len(ports)))
        return out



class ArpTable:
    """Sliding-window record of which MAC(s) claimed each IP (ARP observations)."""

    def __init__(self) -> None:
        self._obs: dict[str, deque] = defaultdict(deque)   # ip -> deque[(ts, mac)]
        self._lock = threading.Lock()

    def observe(self, ip: str, mac: str, ts: float | None = None) -> None:
        ts = _time.time() if ts is None else ts
        with self._lock:
            self._obs[ip].append((ts, _norm_mac(mac)))

    def _prune(self, now: float, window: float) -> None:
        for ip in list(self._obs):
            dq = self._obs[ip]
            while dq and now - dq[0][0] > window:
                dq.popleft()
            if not dq:
                del self._obs[ip]

    def conflicts(self, window: float, now: float | None = None
                  ) -> list[tuple[str, list[str]]]:
        """[(ip, [macs...])] for every IP claimed by 2+ distinct MACs within the
        window — the ARP cache-poisoning signature."""
        now = _time.time() if now is None else now
        out: list[tuple[str, list[str]]] = []
        with self._lock:
            self._prune(now, window)
            for ip, dq in self._obs.items():
                macs = {m for (t, m) in dq if now - t <= window and m}
                if len(macs) >= 2:
                    out.append((ip, sorted(macs)))
        return out



class SnifferState:
    """One object carrying every observation the rule engine consumes."""

    def __init__(self) -> None:
        self.ports = PortScanTracker()
        self.arp = ArpTable()


# --- best-effort live capture (needs Npcap + privilege) ---------------------
_sniffer = None   # scapy AsyncSniffer handle


def start_sniffer(state: SnifferState, iface: str | None = None):
    """Start an AsyncSniffer feeding `state`. Returns the handle, or None if
    Scapy/Npcap is unavailable (the traffic rules then stay dormant)."""
    global _sniffer
    if _sniffer is not None:
        return _sniffer
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import ARP, IP, TCP, AsyncSniffer
    except Exception as e:  # pragma: no cover - import/arch failure
        log.warning("Sniffer unavailable (%s); traffic-based rules disabled.", e)
        return None

    def _on_packet(pkt):
        try:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.psrc and arp.hwsrc:
                    state.arp.observe(arp.psrc, arp.hwsrc)
            elif pkt.haslayer(TCP) and pkt.haslayer(IP):
                flags = int(pkt[TCP].flags)
                if (flags & 0x02) and not (flags & 0x10):   # SYN without ACK
                    state.ports.observe(pkt[IP].src, int(pkt[TCP].dport))
        except Exception:  # pragma: no cover - never let capture crash
            pass

    try:
        kwargs = {"prn": _on_packet, "store": False,
                  "filter": "arp or (tcp[tcpflags] & tcp-syn != 0)"}
        if iface:
            kwargs["iface"] = iface
        handle = AsyncSniffer(**kwargs)
        handle.start()
        _sniffer = handle
        log.info("Traffic sniffer started%s.", f" on {iface}" if iface else "")
        return handle
    except Exception as e:  # pragma: no cover - live capture start failure
        log.warning("Sniffer could not start (%s); traffic rules disabled.", e)
        return None


def stop_sniffer() -> None:
    """Stop the capture thread cleanly (Module 5.1 'must stop on shutdown')."""
    global _sniffer
    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:  # pragma: no cover
            pass
        _sniffer = None
