"""
PWNM web layer (Flask).

LAYERING RULE (from the brief): nothing in web/ imports Scapy or the core
network engine directly. The web layer talks to the database via data/repos and
(from Phase 5) triggers scans through the scheduler — it never sweeps the
network inside a request.
"""
