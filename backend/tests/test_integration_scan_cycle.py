"""
Integration: full scan -> persist -> reconcile cycle via scheduler.scan_cycle,
with the network scanner MOCKED (test DB, no network, no Npcap).

scheduler.scan_cycle() is the real orchestration seam the scheduler runs on a
timer. We drive it directly with a fake scanner so we exercise the real
persistence + reconciliation without touching the LAN.
"""
from data import db, repos
import scheduler
from core import scanner


def _clear():
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM scan_sessions")
    db.execute("DELETE FROM devices")


def _dev(mac, ip):
    return {"mac": mac, "ip": ip, "hostname": "", "vendor": "TestVendor"}


def _pin_target(monkeypatch):
    """Pin the monitor target so scan_cycle doesn't enumerate real adapters."""
    repos.set_setting("monitor_subnet", "192.168.1.0/24")
    repos.set_setting("monitor_interface", "test0")


def test_scan_cycle_persists_discovered_devices(seeded_db, monkeypatch):
    _clear()
    _pin_target(monkeypatch)
    devices = [_dev("aa:11:11:11:11:01", "192.168.1.31"),
               _dev("aa:11:11:11:11:02", "192.168.1.32")]
    monkeypatch.setattr(scheduler.scanner, "discover",
                        lambda iface, subnet, use_fallback=False: devices)

    scheduler.run_scan_cycle(trigger="manual")

    persisted = {d["mac_address"] for d in repos.list_devices()}
    assert persisted == {"aa:11:11:11:11:01", "aa:11:11:11:11:02"}
    scan = repos.last_finished_scan()
    assert scan is not None
    assert scan["devices_found"] == 2
    assert scan["triggered_by"] == "manual"
    # Both devices logged a 'joined' access event.
    joined = db.query_one(
        "SELECT COUNT(*) AS c FROM access_logs WHERE event = 'joined'")
    assert joined["c"] == 2


def test_scan_cycle_falls_back_when_npcap_unavailable(seeded_db, monkeypatch):
    """If the Scapy sweep raises NpcapUnavailable, scan_cycle must prime the ARP
    cache and retry via the fallback — and still persist devices."""
    _clear()
    _pin_target(monkeypatch)
    fallback_devices = [_dev("aa:22:22:22:22:01", "192.168.1.41")]

    def fake_discover(iface, subnet, use_fallback=False):
        if not use_fallback:
            raise scanner.NpcapUnavailable("no Npcap in test")
        return fallback_devices

    primed = {"called": False}
    monkeypatch.setattr(scheduler.scanner, "discover", fake_discover)
    monkeypatch.setattr(scheduler.scanner, "prime_arp_cache",
                        lambda subnet: primed.__setitem__("called", True))

    scheduler.run_scan_cycle(trigger="scheduler")

    assert primed["called"] is True
    assert {d["mac_address"] for d in repos.list_devices()} == {"aa:22:22:22:22:01"}


def test_scan_cycle_reconciles_departed_device(seeded_db, monkeypatch):
    """Across several cycles, a device that stops being discovered is marked
    offline + 'left' exactly once (full cycle through the scheduler)."""
    _clear()
    _pin_target(monkeypatch)
    a, b = "aa:33:33:33:33:01", "aa:33:33:33:33:02"

    def discover_both(iface, subnet, use_fallback=False):
        return [_dev(a, "192.168.1.51"), _dev(b, "192.168.1.52")]

    def discover_only_a(iface, subnet, use_fallback=False):
        return [_dev(a, "192.168.1.51")]

    monkeypatch.setattr(scheduler.scanner, "discover", discover_both)
    scheduler.run_scan_cycle(trigger="scheduler")            # cycle 1: A,B seen

    # B disappears; pin last_seen to the past so every later scan counts as a miss.
    db.execute("UPDATE devices SET last_seen = '2000-01-01 00:00:00' "
               "WHERE mac_address = %s", (b,))

    monkeypatch.setattr(scheduler.scanner, "discover", discover_only_a)
    scheduler.run_scan_cycle(trigger="scheduler")            # cycle 2 (2 misses)
    assert repos.get_device_by_mac(b)["is_online"] == 1       # threshold=3 -> stays
    scheduler.run_scan_cycle(trigger="scheduler")            # cycle 3 (3 misses)

    assert repos.get_device_by_mac(b)["is_online"] == 0       # now offline
    left = db.query_one(
        "SELECT COUNT(*) AS c FROM access_logs al JOIN devices d "
        "ON d.id = al.device_id WHERE d.mac_address = %s AND al.event = 'left'",
        (b,))
    assert left["c"] == 1                                     # exactly one 'left'
    assert repos.get_device_by_mac(a)["is_online"] == 1       # A unaffected


def test_scan_cycle_never_raises_on_scanner_error(seeded_db, monkeypatch):
    """A bad cycle must not propagate — the scheduler has to survive it."""
    _clear()
    _pin_target(monkeypatch)

    def boom(iface, subnet, use_fallback=False):
        raise RuntimeError("adapter exploded mid-scan")

    monkeypatch.setattr(scheduler.scanner, "discover", boom)
    # Must not raise.
    scheduler.run_scan_cycle(trigger="scheduler")


# --- Module 2.4: nmap profiling job (nmap mocked) ---------------------------
def test_profile_devices_stores_ports_and_os(seeded_db, monkeypatch):
    _clear()
    did, _ = repos.upsert_device("aa:44:44:44:44:01", "192.168.1.61", "h", "V")
    monkeypatch.setattr(scheduler.nmap_scan, "nmap_profile",
                        lambda ip: {"ports": [22, 443], "os_guess": "Linux"})
    scheduler.profile_devices()
    dev = repos.get_device(did)
    assert dev["os_guess"] == "Linux"
    assert dev["open_ports"] == "22,443"
    assert repos.devices_needing_profile(10) == []      # not re-profiled


def test_profile_devices_sentinel_when_os_unknown(seeded_db, monkeypatch):
    _clear()
    did, _ = repos.upsert_device("aa:44:44:44:44:02", "192.168.1.62", "h", "V")
    monkeypatch.setattr(scheduler.nmap_scan, "nmap_profile",
                        lambda ip: {"ports": [], "os_guess": ""})
    scheduler.profile_devices()
    # 'unknown' sentinel prevents an endless re-profile loop for hosts nmap can't
    # fingerprint.
    assert repos.get_device(did)["os_guess"] == "unknown"
    assert repos.devices_needing_profile(10) == []
