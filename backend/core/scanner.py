"""
core/scanner.py
===============
LAN device discovery for PWNM. Flask-free; Scapy is imported LAZILY so the
fallback path works even where Scapy/Npcap cannot load. Run standalone:

    python -m core.scanner

Each discovered device is a dict: {ip, mac, vendor, hostname, source}.

TWO DISCOVERY METHODS
---------------------
1. arp_sweep()  — PRIMARY. Broadcasts an ARP "who-has" for every address in the
   subnet (Scapy srp). Every IPv4 host must answer an ARP request for its own
   address, so this finds devices that ignore ping. Needs Npcap + Administrator.

2. arp_table_fallback() — SAFETY NET. Parses the OS ARP cache (`arp -a`). No
   Npcap, no admin. Less complete (only hosts we've recently talked to), so
   prime_arp_cache() can ping the subnet first to fill it in.

WHY MAC, NOT IP: DHCP reshuffles IPs; the MAC is the stable identity used
everywhere downstream. We always report the MAC and treat IP as an attribute.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import interfaces, vendor

log = logging.getLogger(__name__)

# Broadcast/multicast MAC prefixes that appear in the ARP cache but are not real
# hosts. ff:ff:ff=broadcast, 01:00:5e=IPv4 mcast, 33:33=IPv6 mcast, 00:00:00=bad.
_IGNORE_MAC_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33:", "00:00:00")

NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"
NPCAP_HELP = (
    "\n  Scapy could not access the network adapter — Npcap is missing or not "
    "usable.\n"
    f"  1) Install Npcap from:  {NPCAP_DOWNLOAD_URL}\n"
    "     (tick 'Install Npcap in WinPcap API-compatible Mode' during setup)\n"
    "  2) Re-open this terminal AS ADMINISTRATOR, then run the scan again.\n"
    "  Tip: Nmap's installer also bundles Npcap, so installing Nmap covers this.\n"
)

EMPTY_RESULT_DIAGNOSTIC = (
    "\n0 devices found. Check:\n"
    "  - Are you running this terminal as Administrator?\n"
    "  - Did you pick the correct interface (your Wi-Fi, not a VPN/virtual one)?\n"
    "  - Does your router have client / AP isolation enabled?\n"
    "  - Try the arp -a fallback, and/or ping the subnet first (prime).\n"
)


class NpcapUnavailable(RuntimeError):
    """Raised when the Scapy layer-2 path cannot be used (Npcap missing or no
    privilege to open the adapter)."""


def _normalize_mac(raw: str) -> str:
    return raw.replace("-", ":").lower()


# ---------------------------------------------------------------------------
# Method 1: Scapy ARP sweep (primary)
# ---------------------------------------------------------------------------
def arp_sweep(subnet_cidr: str, iface: str | None = None,
              timeout: int = 3, retry: int = 0) -> list[dict]:
    """Broadcast ARP requests across the subnet and collect replies.

    Raises NpcapUnavailable if the packet driver/privilege is missing. Returns
    [] if the driver works but nobody answered (caller decides what that means).
    """
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    if net.num_addresses > 4096:
        log.warning("Subnet %s spans %d addresses — this sweep will be slow.",
                    subnet_cidr, net.num_addresses)

    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # hush import warning
        from scapy.all import ARP, Ether, srp
    except Exception as e:  # import / arch load failure => no usable Scapy
        raise NpcapUnavailable(f"Scapy could not be loaded: {e}") from e

    # One broadcast frame carrying an ARP who-has for the whole subnet; Scapy
    # expands the CIDR pdst into a request per host address.
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))

    def _run(with_iface: bool):
        # retry=0: a continuous monitor runs every scan_interval_seconds anyway,
        # so a device that misses this pass is caught on the NEXT cycle a few
        # seconds later. Scapy's retry>0 resends every UNANSWERED packet (most
        # of a /24 sweep, since only a few hosts are typically up) and waits
        # the full `timeout` again — on Windows/Npcap, dropping retry=1 to 0
        # measured ~31s -> ~24-28s for a /24 sweep. The remaining cost is Npcap
        # packet-injection time for all 254 addresses (confirmed: halving the
        # reply-collection `timeout` changed nothing), not something retry/
        # timeout tuning can remove further — scan_sessions only records time
        # AFTER discovery, so none of this cost is visible there.
        kwargs = {"timeout": timeout, "retry": retry, "verbose": False}
        if with_iface and iface:
            kwargs["iface"] = iface
        return srp(packet, **kwargs)[0]

    try:
        answered = _run(with_iface=True)
    except (ValueError, KeyError) as e:
        # iface name not resolvable by Scapy — retry letting Scapy pick default.
        log.warning("Interface '%s' not resolved by Scapy (%s); using default.",
                    iface, e)
        try:
            answered = _run(with_iface=False)
        except (OSError, RuntimeError) as e2:
            raise NpcapUnavailable(str(e2)) from e2
    except (OSError, RuntimeError) as e:
        raise NpcapUnavailable(str(e)) from e

    devices = []
    for _sent, reply in answered:
        devices.append({
            "ip": reply.psrc,
            "mac": _normalize_mac(reply.hwsrc),
            "vendor": "",
            "hostname": "",
            "source": "arp-sweep",
        })
    return devices


# ---------------------------------------------------------------------------
# Method 2: OS ARP cache (fallback — no Npcap, no admin)
# ---------------------------------------------------------------------------
# One data row of Windows `arp -a`:  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic
_ARP_ROW = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\w+)")


def arp_table_fallback(subnet_cidr: str | None = None) -> list[dict]:
    """Read the OS ARP cache with ``arp -a``. No Npcap/admin. Optionally filter
    to a subnet so entries from other adapters are excluded."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as e:
        log.error("Could not run 'arp -a': %s", e)
        return []

    net = ipaddress.ip_network(subnet_cidr, strict=False) if subnet_cidr else None
    devices, seen = [], set()
    for line in out.splitlines():
        m = _ARP_ROW.match(line)
        if not m:
            continue
        ip, mac_raw, _type = m.groups()
        mac = _normalize_mac(mac_raw)
        if any(mac.startswith(p) for p in _IGNORE_MAC_PREFIXES):
            continue
        if net is not None and ipaddress.ip_address(ip) not in net:
            continue
        if mac in seen:
            continue
        seen.add(mac)
        devices.append({
            "ip": ip, "mac": mac, "vendor": "", "hostname": "",
            "source": "arp-table",
        })
    return devices


def prime_arp_cache(subnet_cidr: str, workers: int = 64,
                    timeout_ms: int = 300) -> None:
    """Ping every host in the subnet in parallel to fill the OS ARP cache,
    making arp_table_fallback() far more complete without Npcap or admin."""
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > 1024:
        log.warning("Refusing to ping-prime %d hosts (range too large).", len(hosts))
        return

    def _ping(ip):
        subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), str(ip)],
                       capture_output=True, text=True)

    log.info("Priming ARP cache: pinging %d hosts on %s ...", len(hosts), subnet_cidr)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_ping, hosts))


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------
def resolve_hostname(ip: str) -> str:
    """Reverse-DNS one IP (Module 2 resolve_hostname). Never raises; returns ""
    on failure. The batch helper below enforces the overall time budget so one
    slow PTR can't stall the sweep."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _resolve_hostnames(ips: list[str], overall_timeout: float = 3.0) -> dict:
    """Reverse-DNS a batch of IPs in parallel with a hard OVERALL time budget.

    Reverse lookups can hang on unresponsive resolvers, so we run them on a
    thread pool and stop collecting after `overall_timeout` — any lookup that
    hasn't finished simply yields "". This guarantees one slow PTR can never
    stall the whole sweep. shutdown(wait=False) means we don't block on stragglers.
    """
    out = {ip: "" for ip in ips}
    if not ips:
        return out
    try:
        pool = ThreadPoolExecutor(max_workers=min(16, len(ips)))
    except RuntimeError:
        # e.g. interpreter is shutting down — hostnames are best-effort, skip.
        return out
    try:
        futures = {pool.submit(resolve_hostname, ip): ip for ip in ips}
        for fut in as_completed(futures, timeout=overall_timeout):
            out[futures[fut]] = fut.result()
    except (TimeoutError, RuntimeError):
        pass  # leftover/again-shutdown lookups stay "" — bounded by design
    finally:
        pool.shutdown(wait=False)
    return out


def enrich(devices: list[dict]) -> list[dict]:
    """Add vendor (OUI/randomised label) and reverse-DNS hostname to each device.

    This is the FAST enrichment run every scan. Open ports + OS estimate are the
    expensive part (nmap) and are added separately on a slower schedule by
    scheduler.profile_devices (Module 2.4), never here in the sweep path.
    """
    for d in devices:
        d["vendor"] = vendor.lookup_vendor(d["mac"])
    hostnames = _resolve_hostnames([d["ip"] for d in devices])
    for d in devices:
        d["hostname"] = hostnames.get(d["ip"], "")
    return devices


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def discover(iface: str | None, subnet: str,
             use_fallback: bool = False) -> list[dict]:
    """Discover devices on `subnet`, enriched with vendor + hostname.

    use_fallback=False -> Scapy ARP sweep (raises NpcapUnavailable if it can't
                          run, so the caller can offer the fallback).
    use_fallback=True  -> OS ARP-cache method (no Npcap/admin).
    """
    if use_fallback:
        devices = arp_table_fallback(subnet)
    else:
        devices = arp_sweep(subnet, iface)        # may raise NpcapUnavailable
    enrich(devices)
    return devices


# ---------------------------------------------------------------------------
# Standalone CLI  (python -m core.scanner)
# ---------------------------------------------------------------------------
def _print_table(devices: list[dict]) -> None:
    header = f"{'IP':<15} | {'MAC':<18} | {'VENDOR':<28} | HOSTNAME"
    print("\n" + header)
    print("-" * (len(header) + 12))
    for d in sorted(devices, key=lambda x: tuple(int(p) for p in x["ip"].split("."))):
        print(f"{d['ip']:<15} | {d['mac']:<18} | "
              f"{(d['vendor'] or 'Unknown')[:28]:<28} | {d['hostname']}")
    print(f"\n{len(devices)} device(s)  (source: {devices[0].get('source', '?')})\n")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(description="PWNM standalone LAN scanner")
    ap.add_argument("--prime", action="store_true",
                    help="ping the subnet first (improves the arp -a fallback)")
    args = ap.parse_args(argv)

    # Numbered interface menu.
    chosen = interfaces.choose_interface()
    if not chosen:
        return 1
    iface, subnet = chosen["name"], chosen["subnet_cidr"]

    # Make sure vendor names can resolve (downloads OUI db once if needed).
    vendor.ensure_db()

    print(f"\nScanning {subnet} on '{iface}' ...")
    if args.prime:
        prime_arp_cache(subnet)

    # Primary path: Scapy sweep. On Npcap failure, explain and offer fallback.
    try:
        devices = discover(iface, subnet, use_fallback=False)
    except NpcapUnavailable as e:
        print(f"\n[Npcap problem] {e}")
        print(NPCAP_HELP)
        answer = input("Run the no-driver `arp -a` fallback instead? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            if not args.prime:
                prime_arp_cache(subnet)      # prime for better fallback coverage
            devices = discover(iface, subnet, use_fallback=True)
        else:
            return 2

    if not devices:
        print(EMPTY_RESULT_DIAGNOSTIC)
        return 0

    _print_table(devices)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
