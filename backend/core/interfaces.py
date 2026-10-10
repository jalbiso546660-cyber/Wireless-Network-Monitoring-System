"""
core/interfaces.py
==================
Network interface discovery for PWNM (standard library + psutil only — no Flask,
no Scapy, so it runs head-less and standalone: ``python -m core.interfaces``).

WHY: before sweeping the LAN we must know (a) WHICH adapter is on the Wi-Fi we
watch, and (b) that adapter's subnet as a CIDR so the ARP sweep has an exact
address range. On Windows a laptop has many adapters (real Wi-Fi + VPN /
VirtualBox / VMware / Hyper-V / WSL virtuals), so we enumerate them, FLAG the
likely-virtual ones, and let the human choose — we never hard-code the NIC.

We also expose get_default_gateway(): the detection engine later needs the
gateway's IP and its baseline MAC, because an ARP-spoofing attacker typically
impersonates the gateway (the gateway's MAC suddenly changing is the signal).
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess

import psutil

# Substrings that usually mark a virtual / tunnelled adapter (not the physical
# Wi-Fi/Ethernet we want). Used only to FLAG (is_virtual), never to auto-drop.
_VIRTUAL_HINTS = (
    "virtualbox", "vmware", "hyper-v", "vethernet", "wsl", "vpn",
    "tap-windows", "tap", "tun", "bluetooth", "npcap loopback", "docker",
    "zerotier", "tailscale", "radmin", "hamachi", "wan miniport", "virtual",
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize_mac(raw: str | None) -> str:
    """Lower-case colon form (aa:bb:cc:dd:ee:ff). psutil gives dash form on
    Windows; we normalise so MACs compare identically everywhere (MAC is the
    device identity)."""
    if not raw:
        return ""
    return raw.replace("-", ":").lower()


def _is_virtual(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _VIRTUAL_HINTS)


def derive_subnet(ipv4: str, netmask: str) -> str:
    """Turn an IP + netmask into the subnet CIDR the sweep will scan.

    ip_interface('192.168.1.23/255.255.255.0').network collapses the host bits
    and yields 192.168.1.0/24 — exactly what Scapy's ARP pdst expects.
    """
    return str(ipaddress.ip_interface(f"{ipv4}/{netmask}").network)


def list_interfaces() -> list[dict]:
    """Enumerate adapters that have an IPv4 address.

    Returns a list of dicts:
        {name, friendly_name, ipv4, netmask, subnet_cidr, is_up, is_virtual, mac}

    Loopback and APIPA/link-local (169.254.x) addresses are filtered out (no
    real LAN there). Adapters that are down are kept but flagged is_up=False so
    the caller can still see them. Note: on Windows psutil exposes only the
    friendly connection name, so `name` and `friendly_name` are the same value —
    both keys are provided for a stable, cross-platform shape.
    """
    stats = psutil.net_if_stats()
    result: list[dict] = []

    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = netmask = mac = None
        for a in addrs:
            if a.family == socket.AF_INET:
                ipv4, netmask = a.address, a.netmask
            elif a.family == psutil.AF_LINK:
                mac = a.address
        if not ipv4 or not netmask:
            continue  # no IPv4 => nothing to sweep on this adapter

        ip_obj = ipaddress.ip_address(ipv4)
        if ip_obj.is_loopback or ip_obj.is_link_local:
            continue  # 127.x or 169.254.x — not a real LAN

        st = stats.get(name)
        result.append({
            "name": name,
            "friendly_name": name,
            "ipv4": ipv4,
            "netmask": netmask,
            "subnet_cidr": derive_subnet(ipv4, netmask),
            "is_up": bool(st.isup) if st else False,
            "is_virtual": _is_virtual(name),
            "mac": _normalize_mac(mac),
        })

    # Convenience ordering for the menu: up & physical first.
    result.sort(key=lambda i: (not i["is_up"], i["is_virtual"], i["name"]))
    return result


def _gateway_mac_from_arp(gateway_ip: str) -> str:
    """Look up the gateway's MAC in the OS ARP cache (`arp -a`)."""
    try:
        out = subprocess.run(["arp", "-a", gateway_ip],
                             capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", out)
    return _normalize_mac(m.group(1)) if m else ""


def get_default_gateway() -> dict | None:
    """Return the system default gateway as {ip, mac, interface_ip}, or None.

    We read the routing table (`route print -4 0.0.0.0`) rather than parsing
    ipconfig, because the default route is identified by the numeric
    destination/netmask 0.0.0.0 — which is language-independent (ipconfig's
    "Default Gateway" label is localised). When several default routes exist we
    pick the one with the lowest metric (the interface actually in use). The
    gateway MAC is then read from the ARP cache for the ARP-spoof baseline.
    """
    try:
        out = subprocess.run(["route", "print", "-4", "0.0.0.0"],
                             capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    candidates = []  # (metric, gateway_ip, interface_ip)
    for line in out.splitlines():
        parts = line.split()
        # Default-route row: 0.0.0.0  0.0.0.0  <gateway>  <iface_ip>  <metric>
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw, iface_ip = parts[2], parts[3]
            if not _IPV4_RE.match(gw):
                continue  # skip 'On-link' or malformed rows
            try:
                metric = int(parts[4])
            except ValueError:
                metric = 9999
            candidates.append((metric, gw, iface_ip))

    if not candidates:
        return None
    candidates.sort()
    _metric, gw_ip, iface_ip = candidates[0]
    return {
        "ip": gw_ip,
        "mac": _gateway_mac_from_arp(gw_ip),
        "interface_ip": iface_ip,
    }


def _print_menu(interfaces: list[dict]) -> None:
    header = (f"{'#':>2}  {'Interface':<28} {'IPv4':<15} "
              f"{'Subnet (CIDR)':<19} {'Up':<3} Note")
    print(header)
    print("-" * (len(header) + 6))
    for i, itf in enumerate(interfaces, 1):
        note = "virtual/VPN?" if itf["is_virtual"] else ""
        print(f"{i:>2}  {itf['friendly_name'][:28]:<28} {itf['ipv4']:<15} "
              f"{itf['subnet_cidr']:<19} {'yes' if itf['is_up'] else 'no':<3} {note}")


def choose_interface(interfaces: list[dict] | None = None) -> dict | None:
    """Show a numbered menu and return the chosen interface dict (or None).

    Used by ``python -m core.scanner`` so interface selection behaves
    identically everywhere. The default (Enter) is item 1, which
    list_interfaces() has already ranked as the most likely real adapter.
    """
    interfaces = interfaces if interfaces is not None else list_interfaces()
    if not interfaces:
        print("No usable IPv4 interface found. Are you connected to Wi-Fi?")
        return None

    print("\nAvailable network interfaces:\n")
    _print_menu(interfaces)
    while True:
        raw = input(f"\nChoose interface [1-{len(interfaces)}] (Enter = 1): ").strip()
        if raw == "":
            return interfaces[0]
        if raw.isdigit() and 1 <= int(raw) <= len(interfaces):
            return interfaces[int(raw) - 1]
        print("  Invalid choice, try again.")


if __name__ == "__main__":
    ifaces = list_interfaces()
    if not ifaces:
        print("No usable interfaces (need an adapter with a private IPv4).")
    else:
        _print_menu(ifaces)
        gw = get_default_gateway()
        if gw:
            print(f"\nDefault gateway: {gw['ip']}  (MAC {gw['mac'] or 'unknown'}) "
                  f"via {gw['interface_ip']}")
        best = ifaces[0]
        print(f"Best-guess adapter: '{best['friendly_name']}' -> sweep {best['subnet_cidr']}")
