"""PWNM detection engine (Phase 6).

Pure rule logic lives in `rules.py` (no DB, no network — fully unit-testable).
`sniffer.py` holds the port-scan sliding-window tracker plus a best-effort Scapy
capture thread. `engine.py` wires the rules to the data layer, de-duplicates, and
persists alerts; it is called once per scan cycle by the scheduler.
"""
