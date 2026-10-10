"""
Unit tests for core.interfaces.derive_subnet — pure, no network, no DB.

derive_subnet(ip, netmask) collapses host bits and returns the CIDR the ARP
sweep will scan. We assert known IP/netmask pairs plus edge cases (/8, /16,
/25, /30, /32) and malformed input.
"""
import pytest

from core.interfaces import derive_subnet


@pytest.mark.parametrize("ip, netmask, expected", [
    # Classic home LAN.
    ("192.168.1.23", "255.255.255.0", "192.168.1.0/24"),
    # Host bits must be dropped, not preserved.
    ("192.168.1.200", "255.255.255.0", "192.168.1.0/24"),
    # /16 and /8.
    ("172.16.5.4", "255.255.0.0", "172.16.0.0/16"),
    ("10.0.0.5", "255.0.0.0", "10.0.0.0/8"),
    # Non-octet-aligned masks.
    ("192.168.1.130", "255.255.255.128", "192.168.1.128/25"),   # /25 upper half
    ("192.168.1.126", "255.255.255.128", "192.168.1.0/25"),     # /25 lower half
    ("192.168.1.6", "255.255.255.252", "192.168.1.4/30"),       # /30 block
    # Single-host edge.
    ("192.168.1.1", "255.255.255.255", "192.168.1.1/32"),
    # Whole-internet edge.
    ("192.168.1.1", "0.0.0.0", "0.0.0.0/0"),
])
def test_derive_subnet_known_pairs(ip, netmask, expected):
    assert derive_subnet(ip, netmask) == expected


@pytest.mark.parametrize("ip, netmask", [
    ("999.1.1.1", "255.255.255.0"),      # invalid octet
    ("192.168.1.1", "255.255.255.1"),    # non-contiguous mask
    ("not-an-ip", "255.255.255.0"),      # garbage
])
def test_derive_subnet_rejects_bad_input(ip, netmask):
    with pytest.raises(ValueError):
        derive_subnet(ip, netmask)
