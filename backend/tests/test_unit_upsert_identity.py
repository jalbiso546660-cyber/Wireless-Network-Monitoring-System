"""
Identity logic for repos.upsert_device (test DB, no network).

The MAC address is the device identity (devices.mac_address is UNIQUE), so:
  * same MAC + different IP  -> ONE row, last_ip updated (DHCP churn);
  * different MAC + same IP  -> TWO rows (IP is not an identity);
  * a routine re-scan must NOT overwrite admin decisions (status) or wipe
    previously-known attributes when the new scan reports nothing for them.
"""
from data import db, repos


def _clear_devices():
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM devices")


def _count(mac):
    row = db.query_one(
        "SELECT COUNT(*) AS c FROM devices WHERE mac_address = %s", (mac,))
    return row["c"]


def test_same_mac_different_ip_keeps_one_row(seeded_db):
    _clear_devices()
    mac = "11:22:33:44:55:66"

    id1, new1 = repos.upsert_device(mac, "192.168.1.10", "host-a", "VendorA")
    assert new1 is True

    id2, new2 = repos.upsert_device(mac, "192.168.1.99", "host-a", "VendorA")
    assert new2 is False
    assert id2 == id1                      # same row reused
    assert _count(mac) == 1                # NOT a second row

    row = repos.get_device_by_mac(mac)
    assert row["last_ip"] == "192.168.1.99"   # IP updated in place


def test_different_mac_same_ip_creates_two_rows(seeded_db):
    _clear_devices()
    ip = "10.0.0.5"
    id_a, _ = repos.upsert_device("aa:aa:aa:aa:aa:aa", ip, "a", "V")
    id_b, _ = repos.upsert_device("bb:bb:bb:bb:bb:bb", ip, "b", "V")

    assert id_a != id_b
    rows = db.query("SELECT id FROM devices WHERE last_ip = %s", (ip,))
    assert len(rows) == 2                  # two distinct devices on one IP


def test_rescan_does_not_overwrite_admin_status(seeded_db):
    _clear_devices()
    mac = "de:ad:be:ef:00:01"
    did, _ = repos.upsert_device(mac, "192.168.1.20", "h", "V")
    repos.set_device_status(did, "authorized", authorized_by=None)

    # A later routine scan re-sees the device.
    repos.upsert_device(mac, "192.168.1.20", "h", "V")

    assert repos.get_device(did)["status"] == "authorized"   # decision preserved


def test_rescan_with_missing_attrs_keeps_known_values(seeded_db):
    _clear_devices()
    mac = "de:ad:be:ef:00:02"
    did, _ = repos.upsert_device(mac, "192.168.1.30", "known-host", "KnownVendor")

    # Next scan can't resolve hostname/vendor (passes None) — COALESCE must keep
    # the previously-known values instead of nulling them.
    repos.upsert_device(mac, "192.168.1.31", None, None)

    row = repos.get_device(did)
    assert row["hostname"] == "known-host"
    assert row["vendor"] == "KnownVendor"
    assert row["last_ip"] == "192.168.1.31"      # IP still tracks latest


def test_is_online_set_on_upsert(seeded_db):
    _clear_devices()
    mac = "de:ad:be:ef:00:03"
    did, _ = repos.upsert_device(mac, "192.168.1.40", "h", "V")
    assert repos.get_device(did)["is_online"] == 1
