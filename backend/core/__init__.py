"""
PWNM network engine (``core`` package).

LAYERING RULE (from the project brief): nothing in this package may import
Flask or touch the database. Everything here is pure network/OS logic so each
module can be run and tested on its own, e.g.::

    python -m core.interfaces
    python -m core.scanner --method arp

Keeping the engine Flask-free is a security/architecture decision: the code
that talks to the network runs in background jobs, never inside a web request,
so a slow or hostile network can never stall the web server.
"""
