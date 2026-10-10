"""
core/vendor.py
==============
MAC address -> manufacturer, with two special behaviours the project needs:

  * lookup(mac) returns "Unknown" on any miss and NEVER raises;
  * a locally-administered (randomised) MAC returns "Randomized (private MAC)"
    instead of a vendor. Modern phones rotate their MAC for privacy, so a
    "returning" device can look brand-new — this label makes that visible and
    is one of the project's documented limitations.

HOW WE DETECT RANDOMISED MACs
-----------------------------
The least-significant two bits of the FIRST octet are special:
    bit 0 (0x01) = multicast flag
    bit 1 (0x02) = "locally administered" flag  <-- this one
When bit 1 is set, the address was assigned by software (randomised / private),
not burned in by a manufacturer, so there is no IEEE OUI to look up.

OUI DATA SOURCE
---------------
We use the pinned ``mac-vendor-lookup`` library as the offline lookup engine,
but feed its cache from the Wireshark ``manuf`` registry instead of the
library's built-in IEEE URL — that URL now returns HTTP 418 (bot-blocked) and
silently writes a 0-byte cache. See _build_cache_from_wireshark().

No Flask, no database.
"""
from __future__ import annotations

import logging
import os
import urllib.request

log = logging.getLogger(__name__)

WIRESHARK_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
_MIN_VALID_CACHE_BYTES = 100_000

RANDOMISED_LABEL = "Randomized (private MAC)"
UNKNOWN_LABEL = "Unknown"

# In-memory result cache: normalised MAC -> vendor string. Avoids re-parsing the
# 40k-entry OUI table per device and makes repeated scans cheap.
_cache: dict[str, str] = {}

# Import the library defensively — a broken/missing library must never stop a scan.
try:
    from mac_vendor_lookup import BaseMacLookup, MacLookup, VendorNotFoundError
    _AVAILABLE = True
except Exception as _e:  # pragma: no cover
    log.warning("mac-vendor-lookup unavailable (%s); vendors will be 'Unknown'.", _e)
    _AVAILABLE = False
    BaseMacLookup = None  # type: ignore

    class VendorNotFoundError(Exception):  # type: ignore
        pass

_engine = None          # lazily-created MacLookup instance
_ensure_attempted = False


# --- normalisation & randomised-MAC detection -------------------------------
def _normalize(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_locally_administered(mac: str) -> bool:
    """True if the MAC is locally-administered (randomised/private).

    Reads bit 0x02 of the first octet. Returns False for anything unpar. Safe
    on both colon and dash formats.
    """
    try:
        first_octet = int(_normalize(mac).split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return False
    return bool(first_octet & 0x02)


# --- offline OUI cache management --------------------------------------------
def _cache_path() -> str:
    return BaseMacLookup.cache_path if _AVAILABLE else ""


def _ensure_cache_dir() -> None:
    """Create ~/.cache (mac-vendor-lookup's default location) — it does not
    exist by default on Windows, which otherwise breaks the download."""
    path = _cache_path()
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)


def _cache_is_valid() -> bool:
    try:
        return os.path.getsize(_cache_path()) >= _MIN_VALID_CACHE_BYTES
    except OSError:
        return False


def _build_cache_from_wireshark(url: str = WIRESHARK_MANUF_URL,
                                timeout: int = 60) -> int:
    """Download Wireshark's ``manuf`` file and write it into the
    mac-vendor-lookup cache in that library's ``PREFIX:Vendor`` format. Only
    24-bit OUIs are kept (the engine keys on the first 6 hex digits). Returns
    the number of entries written."""
    _ensure_cache_dir()
    req = urllib.request.Request(url, headers={"User-Agent": "PWNM/1.0"})
    count = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp, \
            open(_cache_path(), "wb") as out:
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            prefix = parts[0].strip()
            if "/" in prefix:                 # masked block > /24 — skip
                continue
            hexp = prefix.replace(":", "").replace("-", "").upper()
            if len(hexp) != 6:
                continue
            vendor = ""
            if len(parts) >= 3 and parts[2].strip():
                vendor = parts[2].strip()
            elif len(parts) >= 2 and parts[1].strip():
                vendor = parts[1].strip()
            if not vendor:
                continue
            out.write(f"{hexp}:{vendor}\n".encode("utf-8"))
            count += 1
    return count


def ensure_db(force: bool = False) -> bool:
    """Build/refresh the offline OUI cache from Wireshark. Needs internet ONCE;
    a no-op if a valid cache already exists. Safe to call anytime."""
    global _engine
    if not _AVAILABLE:
        return False
    if not force and _cache_is_valid():
        return True
    try:
        n = _build_cache_from_wireshark()
        if n == 0:
            log.warning("OUI source returned no usable entries.")
            return False
        log.info("OUI vendor database built: %d entries.", n)
        _engine = None            # force reload from the fresh cache
        _cache.clear()
        return True
    except OSError as e:
        log.warning("Could not build OUI database: %s", e)
        return False


def _get_engine():
    global _engine
    if _engine is None and _AVAILABLE:
        try:
            _engine = MacLookup()
        except Exception as e:  # pragma: no cover
            log.warning("MacLookup init failed: %s", e)
            _engine = None
    return _engine


# --- public API --------------------------------------------------------------
def lookup_vendor(mac: str) -> str:
    """Return the manufacturer for ``mac`` (Module 2 lookup_vendor). Never raises.

    Order: cache -> randomised-MAC label -> offline OUI lookup -> 'Unknown'.
    """
    global _ensure_attempted
    if not mac:
        return UNKNOWN_LABEL

    key = _normalize(mac)
    if key in _cache:
        return _cache[key]

    # Randomised/private MACs have no manufacturer OUI — label and return.
    if is_locally_administered(key):
        _cache[key] = RANDOMISED_LABEL
        return RANDOMISED_LABEL

    engine = _get_engine()
    if engine is None:
        return UNKNOWN_LABEL

    # First real lookup on a fresh machine: build the cache once (best-effort).
    if not _ensure_attempted and not _cache_is_valid():
        _ensure_attempted = True
        ensure_db()
        engine = _get_engine()

    try:
        result = engine.lookup(key)
    except VendorNotFoundError:
        result = UNKNOWN_LABEL
    except Exception:
        # FileNotFoundError (no cache), randomised MAC edge cases, parse hiccups
        result = UNKNOWN_LABEL

    _cache[key] = result
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    print("Ensuring OUI database (downloads from Wireshark the first time) ...")
    print("database ready:", ensure_db(), "\n")
    samples = [
        ("a4:83:e7:11:22:33", "Apple (real OUI)"),
        ("3c:5a:b4:11:22:33", "Google (real OUI)"),
        ("e6:b3:18:55:f8:07", "locally-administered -> Randomized"),
        ("fe:72:41:71:9d:a6", "locally-administered -> Randomized"),
        ("", "empty -> Unknown"),
    ]
    for mac, expect in samples:
        print(f"  {mac or '(empty)':<20} -> {lookup_vendor(mac):<26} (expected: {expect})")
