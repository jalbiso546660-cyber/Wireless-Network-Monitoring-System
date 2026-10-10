"""
core/nmap_scan.py — nmap_profile with python-nmap MOCKED (no real scan, no admin).
"""
from core import nmap_scan


class _FakeScanner:
    def __init__(self, hostmap):
        self._hostmap = hostmap

    def scan(self, hosts=None, arguments=None):
        return {}

    def all_hosts(self):
        return list(self._hostmap)

    def __getitem__(self, h):
        return self._hostmap[h]


def _host(open_ports, os_name=None):
    tcp = {p: {"state": "open"} for p in open_ports}
    tcp[9999] = {"state": "closed"}          # a closed port must be ignored
    host = {"tcp": tcp}
    if os_name:
        host["osmatch"] = [{"name": os_name}]
    return host


def test_nmap_profile_returns_open_ports_and_os(monkeypatch):
    fake = _FakeScanner({"10.0.0.5": _host([80, 22], "Linux 5.X")})
    monkeypatch.setattr(nmap_scan, "_AVAILABLE", True)
    monkeypatch.setattr(nmap_scan.nmap, "PortScanner", lambda: fake)
    prof = nmap_scan.nmap_profile("10.0.0.5")
    assert prof["ports"] == [22, 80]         # sorted, closed port excluded
    assert prof["os_guess"] == "Linux 5.X"


def test_nmap_profile_ports_without_os(monkeypatch):
    fake = _FakeScanner({"10.0.0.6": _host([443])})   # no osmatch (no admin)
    monkeypatch.setattr(nmap_scan, "_AVAILABLE", True)
    monkeypatch.setattr(nmap_scan.nmap, "PortScanner", lambda: fake)
    prof = nmap_scan.nmap_profile("10.0.0.6")
    assert prof["ports"] == [443]
    assert prof["os_guess"] == ""


def test_nmap_profile_empty_when_unavailable(monkeypatch):
    monkeypatch.setattr(nmap_scan, "_AVAILABLE", False)
    assert nmap_scan.nmap_profile("10.0.0.5") == {"ports": [], "os_guess": ""}


def test_nmap_profile_empty_when_scan_fails(monkeypatch):
    class _Boom:
        def scan(self, **kw):
            raise RuntimeError("nmap needs privilege")
        def all_hosts(self):
            return []
    monkeypatch.setattr(nmap_scan, "_AVAILABLE", True)
    monkeypatch.setattr(nmap_scan.nmap, "PortScanner", lambda: _Boom())
    assert nmap_scan.nmap_profile("10.0.0.5") == {"ports": [], "os_guess": ""}


def test_nmap_profile_no_ip():
    assert nmap_scan.nmap_profile("") == {"ports": [], "os_guess": ""}
