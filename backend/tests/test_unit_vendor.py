"""
Unit tests for core.vendor — pure logic, no network.

Covers:
  * is_locally_administered(): the randomised/private-MAC bit (0x02 of octet 1),
    including the True/False boundary and malformed input;
  * lookup(): empty -> Unknown, randomised -> the private-MAC label, a real OUI
    hit (engine is faked so no OUI download / network is needed), an OUI miss
    -> Unknown, and that results are cached.

The OUI engine is replaced with a deterministic fake so these tests never touch
the network or the on-disk OUI cache.
"""
import pytest

from core import vendor


@pytest.fixture(autouse=True)
def _isolate_vendor(monkeypatch):
    """Clear the module cache and neutralise the one-time DB-build attempt so
    each test is deterministic and offline."""
    vendor._cache.clear()
    # Pretend the one-time cache build already happened, so lookup() never tries
    # to hit the network.
    monkeypatch.setattr(vendor, "_ensure_attempted", True, raising=False)
    yield
    vendor._cache.clear()


class _FakeEngine:
    """Stand-in for mac_vendor_lookup.MacLookup with a fixed OUI table."""
    def __init__(self, table):
        self.table = table
        self.calls = 0

    def lookup(self, mac):
        self.calls += 1
        key = mac.lower()
        for prefix, name in self.table.items():
            if key.startswith(prefix):
                return name
        raise vendor.VendorNotFoundError(mac)


# --- is_locally_administered -------------------------------------------------
@pytest.mark.parametrize("mac", [
    "02:00:00:00:00:00",   # 0x02 set (canonical LA)
    "06:11:22:33:44:55",
    "0a:11:22:33:44:55",
    "0e:11:22:33:44:55",
    "e6:b3:18:55:f8:07",   # real-world randomised phone MAC
    "fe:72:41:71:9d:a6",
    "AA-BB-CC-DD-EE-FF",   # dash form, 0xAA has 0x02 set
])
def test_locally_administered_true(mac):
    assert vendor.is_locally_administered(mac) is True


@pytest.mark.parametrize("mac", [
    "a4:83:e7:11:22:33",   # Apple OUI, 0x02 clear
    "3c:5a:b4:11:22:33",   # Google OUI, 0x02 clear
    "00:11:22:33:44:55",   # 0x00
    "f0:11:22:33:44:55",   # 0xF0, 0x02 clear
    "fc:11:22:33:44:55",   # 0xFC, 0x02 clear
])
def test_locally_administered_false(mac):
    assert vendor.is_locally_administered(mac) is False


@pytest.mark.parametrize("bad", ["", "zz:zz:zz", "nonsense", None])
def test_locally_administered_bad_input_is_false(bad):
    # Never raises; unparseable input is treated as not-LA.
    assert vendor.is_locally_administered(bad) is False


# --- lookup ------------------------------------------------------------------
def test_lookup_empty_is_unknown():
    assert vendor.lookup_vendor("") == vendor.UNKNOWN_LABEL


def test_lookup_randomised_is_labelled(monkeypatch):
    # A randomised MAC must be labelled BEFORE any OUI lookup — no engine needed.
    monkeypatch.setattr(vendor, "_get_engine", lambda: None)
    assert vendor.lookup_vendor("e6:b3:18:55:f8:07") == vendor.RANDOMISED_LABEL


def test_lookup_real_oui_hit(monkeypatch):
    fake = _FakeEngine({"a4:83:e7": "Apple, Inc.", "3c:5a:b4": "Google, Inc."})
    monkeypatch.setattr(vendor, "_get_engine", lambda: fake)
    assert vendor.lookup_vendor("a4:83:e7:11:22:33") == "Apple, Inc."
    assert vendor.lookup_vendor("3c:5a:b4:aa:bb:cc") == "Google, Inc."


def test_lookup_oui_miss_is_unknown(monkeypatch):
    fake = _FakeEngine({"a4:83:e7": "Apple, Inc."})
    monkeypatch.setattr(vendor, "_get_engine", lambda: fake)
    assert vendor.lookup_vendor("00:11:22:33:44:55") == vendor.UNKNOWN_LABEL


def test_lookup_caches_result(monkeypatch):
    fake = _FakeEngine({"a4:83:e7": "Apple, Inc."})
    monkeypatch.setattr(vendor, "_get_engine", lambda: fake)
    assert vendor.lookup_vendor("a4:83:e7:11:22:33") == "Apple, Inc."
    assert fake.calls == 1
    # Second call must be served from cache (engine not consulted again).
    assert vendor.lookup_vendor("A4:83:E7:11:22:33") == "Apple, Inc."
    assert fake.calls == 1
