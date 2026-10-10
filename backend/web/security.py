"""
web/security.py
===============
App-wide security wiring that isn't specific to authentication:

  * CSRF protection for every state-changing request (POST/PUT/PATCH/DELETE),
    implemented with a per-session token — no external dependency (Flask-WTF is
    not in the pinned list). Templates emit the token via {{ csrf_token() }}.
  * A few defensive response headers.

CSRF matters here because the app performs state changes from the browser
(login, later: authorize/block a device, edit settings). Without a CSRF token a
malicious page could make your browser POST those actions using your session
cookie. SameSite=Lax on the cookie is the first layer; this token is the second.
"""
from __future__ import annotations

import secrets

from flask import abort, request, session

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def get_csrf_token() -> str:
    """Return the session's CSRF token, creating one on first use."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["_csrf_token"] = token
    return token


def init_security(app) -> None:
    @app.before_request
    def _csrf_protect():
        if request.method in _SAFE_METHODS:
            return
        sent = (request.form.get("_csrf_token")
                or request.headers.get("X-CSRF-Token"))
        expected = session.get("_csrf_token")
        # Constant-time compare; reject if missing or mismatched.
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="CSRF token missing or invalid.")

    @app.context_processor
    def _inject_csrf():
        # Exposes csrf_token() to every template.
        return {"csrf_token": get_csrf_token}

    @app.context_processor
    def _inject_unread_alerts():
        # Severity-weighted unread-alert summary for the nav badge (Module 6.2).
        # Only query for authenticated users and never let a DB hiccup break a
        # page render.
        from flask_login import current_user

        from data import repos
        blank = {"count": 0, "weight": 0, "top_severity": None}
        try:
            if current_user.is_authenticated:
                return {"unread_alerts": repos.get_unread_count()}
        except Exception:
            pass
        return {"unread_alerts": blank}

    # Content-Security-Policy. script-src is STRICT (no 'unsafe-inline') so an
    # injected <script> or inline handler cannot run — the important XSS defence.
    # style-src allows 'unsafe-inline' only because templates use style="" attrs
    # and Bootstrap injects styles; that is far lower risk than script injection.
    # The jsdelivr origin is the CDN that serves Bootstrap, Chart.js and the
    # Bootstrap-Icons font (self-host these later to drop the CDN allowance).
    _CDN = "https://cdn.jsdelivr.net"
    _CSP = "; ".join([
        "default-src 'self'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "object-src 'none'",
        "img-src 'self' data:",
        f"script-src 'self' {_CDN}",
        f"style-src 'self' 'unsafe-inline' {_CDN}",
        f"font-src 'self' {_CDN} data:",
        "connect-src 'self'",
    ])

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", _CSP)
        resp.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
        # HSTS is only honoured over HTTPS; harmless (and ignored) on plain HTTP,
        # so it activates automatically if the app is ever put behind TLS.
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
        return resp
