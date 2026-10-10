"""
app.py
======
PWNM Flask application factory.

Responsibilities (Phase 4):
  * load config, harden the session cookie, fail loudly if SECRET_KEY is unset;
  * initialise the DB pool (warn, not crash, if the DB is down at boot);
  * register blueprints and Flask-Login;
  * wire CSRF + security headers;
  * register 400/403/404/500 error handlers.

NOTE: the APScheduler scan loop is deliberately NOT started here — that is
Phase 5. Scans must never run inside a web request.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys

from flask import Flask, render_template, request

import config
from data import db
from web.routes.alerts import alerts_bp
from web.routes.charts import charts_bp
from web.routes.auth import auth_bp, login_manager
from web.routes.dashboard import dashboard_bp
from web.routes.devices import devices_bp
from web.routes.reports import reports_bp
from web.routes.settings import settings_bp
from web.security import init_security

# Values that mean "no real secret was configured".
_INSECURE_SECRETS = {"", None, "dev-only-insecure-change-me",
                     "change-me-to-a-random-secret"}

_LOGGING_READY = False
_LOG_FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_LOG_DATEFMT = "%H:%M:%S"


def _configure_logging() -> None:
    """Set up console logging + levels once (safe in EVERY process).

      * PWNM_LOG_LEVEL=DEBUG|INFO|WARNING  (default: DEBUG in dev, else INFO)
      * noisy third-party loggers are turned down so YOUR logs stand out.

    The rotating FILE handler is added separately by _add_file_logging() in the
    single serving process only: on Windows two processes writing one rotating
    file collide on rollover (the reloader runs a parent watcher + a child).
    Skipped entirely under pytest so the test suite's logging is untouched.
    """
    global _LOGGING_READY
    if _LOGGING_READY or "pytest" in sys.modules:
        return

    default_level = "DEBUG" if os.getenv("PWNM_DEBUG", "1") == "1" else "INFO"
    level = getattr(logging, os.getenv("PWNM_LOG_LEVEL", default_level).upper(),
                    logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_LOG_FMT, datefmt=_LOG_DATEFMT))
    root.addHandler(console)

    # Quiet the chatty libraries so app logs (and request traces) stay readable.
    logging.getLogger("mysql.connector").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.INFO)
    logging.getLogger("werkzeug").setLevel(logging.INFO)

    _LOGGING_READY = True


def _add_file_logging() -> None:
    """Attach the rotating file handler (backend/logs/pwnm.log). Call ONLY from
    the process that serves requests, so the file has a single writer (avoids the
    Windows rollover clash). delay=True opens the file lazily on first record."""
    root = logging.getLogger()
    if any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        return
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "pwnm.log"), maxBytes=1_000_000, backupCount=5,
        encoding="utf-8", delay=True)
    fh.setFormatter(logging.Formatter(_LOG_FMT, datefmt=_LOG_DATEFMT))
    root.addHandler(fh)


def create_app() -> Flask:
    _configure_logging()

    # Frontend (Jinja templates + CSS/JS) lives in a sibling ../frontend folder,
    # separate from the backend package. Resolve it absolutely from this file so
    # the app works regardless of the current working directory.
    _BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
    _FRONTEND_DIR = os.path.normpath(os.path.join(_BACKEND_DIR, os.pardir, "frontend"))
    app = Flask(__name__,
                template_folder=os.path.join(_FRONTEND_DIR, "templates"),
                static_folder=os.path.join(_FRONTEND_DIR, "static"))

    # --- SECRET_KEY: fail loudly if missing / still a placeholder ----------
    if config.SECRET_KEY in _INSECURE_SECRETS:
        raise RuntimeError(
            "SECRET_KEY is missing or is a placeholder. Set a real random value "
            "in .env:\n  python -c \"import secrets; print(secrets.token_hex(32))\"")
    app.config["SECRET_KEY"] = config.SECRET_KEY

    # --- Hardened session cookie -----------------------------------------
    # SECURE is opt-in via env so it can be turned on (with no code change) the
    # day this is served over HTTPS; it stays False for plain-HTTP localhost dev.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,    # JavaScript cannot read it (XSS mitigation)
        SESSION_COOKIE_SAMESITE="Lax",   # not sent on cross-site POST (CSRF mitigation)
        SESSION_COOKIE_SECURE=(os.getenv("PWNM_COOKIE_SECURE", "0") == "1"),
    )

    # Templates are re-read when they change even with the debugger off, so
    # editing a .html file never requires restarting the app (LAN mode runs
    # debug=False). Costs one stat() per render — negligible here.
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    # --- Confirm Jinja autoescape (defence in depth vs. XSS) --------------
    if app.select_jinja_autoescape("x.html") is not True:
        raise RuntimeError("Jinja autoescaping is not enabled for HTML templates.")

    # --- Data pool (probe at boot so misconfig is visible immediately) ----
    if not db.ping():
        logging.warning("Database not reachable at startup — check that XAMPP "
                        "MySQL is running and .env is correct. The login page "
                        "will error until the DB is up.")

    # --- Template helpers -----------------------------------------------
    from data.repos import rule_explain, rule_label, status_label
    app.jinja_env.filters["status_label"] = status_label   # blocked -> "flagged"
    app.jinja_env.filters["rule_label"] = rule_label        # UNAUTH_NEW -> "New unknown device"
    app.jinja_env.filters["rule_explain"] = rule_explain    # one-line meaning

    # --- Flask-Login, CSRF, headers --------------------------------------
    login_manager.init_app(app)
    init_security(app)

    # --- Blueprints -------------------------------------------------------
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(charts_bp)

    # --- Error handlers ---------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("400.html",
                               reason=getattr(e, "description", None)), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        logging.exception("Unhandled server error")
        return render_template("500.html"), 500

    # --- Debugging aids ---------------------------------------------------
    # Per-request trace at DEBUG level: method, path, status AND the endpoint
    # that served it (Werkzeug's own line doesn't show the endpoint).
    @app.after_request
    def _trace_request(resp):
        logging.getLogger("pwnm.request").debug(
            "%s %s -> %s [%s]", request.method, request.path,
            resp.status_code, request.endpoint)
        return resp

    # One-line snapshot of the effective runtime config, so a glance at the log
    # shows exactly what this process is wired to.
    logging.getLogger("pwnm").info(
        "app ready - DB=%s:%s/%s  cookie_secure=%s  templates=%s",
        config.DB_HOST, config.DB_PORT, config.DB_NAME,
        app.config["SESSION_COOKIE_SECURE"], app.template_folder)

    return app


# Logging is configured inside create_app() (via _configure_logging), so it is
# ready no matter how the app is started — `python app.py`, `flask run`, or a
# WSGI server importing this module.
app = create_app()


def _lan_urls(port: int) -> list[str]:
    """Best-guess http URLs other devices on the LAN can open."""
    try:
        from core import interfaces          # psutil only, no Scapy
        return [f"http://{i['ipv4']}:{port}" for i in interfaces.list_interfaces()
                if i.get("is_up") and not i.get("is_virtual")]
    except Exception:
        return []


if __name__ == "__main__":
    from scheduler import start_scheduler

    log = logging.getLogger("pwnm")
    PORT = int(os.getenv("PWNM_PORT", "5000"))

    # HOST: 0.0.0.0 serves every network interface, so phones/laptops on the same
    # Wi-Fi can open the dashboard (LAN deployment). Set PWNM_HOST=127.0.0.1 to
    # go back to this-machine-only.
    HOST = os.getenv("PWNM_HOST", "0.0.0.0")
    LOOPBACK_ONLY = HOST in ("127.0.0.1", "localhost", "::1")

    # DEBUG is env-driven and defaults ON for local development (auto-reload +
    # interactive tracebacks). For a real deployment run with PWNM_DEBUG=0.
    DEBUG = os.getenv("PWNM_DEBUG", "1") == "1"

    # SAFETY: Werkzeug's interactive debugger is a remote-code-execution console.
    # It must never be reachable from the network, so binding beyond loopback
    # disables it regardless of PWNM_DEBUG.
    if DEBUG and not LOOPBACK_ONLY:
        log.warning("Serving on %s (LAN): the interactive debugger is DISABLED "
                    "because it would be an RCE risk for anyone on this network. "
                    "Use PWNM_HOST=127.0.0.1 for debug mode.", HOST)
        DEBUG = False

    USE_RELOADER = DEBUG   # Flask's reloader runs a parent watcher + a child server

    # Start the scan loop in the process that ACTUALLY serves requests, exactly
    # once:
    #   * reloader ON  -> only the child sets WERKZEUG_RUN_MAIN='true'; the parent
    #     watcher must NOT start a second scheduler (this is the debug-mode trap).
    #   * reloader OFF -> single process, WERKZEUG_RUN_MAIN unset -> start here.
    if (not USE_RELOADER) or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        _add_file_logging()          # single writer -> no Windows rollover clash
        start_scheduler(app)
        log.info("scan scheduler started")

    log.info("serving on http://127.0.0.1:%d  (debug=%s)  -  Ctrl+C to stop",
             PORT, DEBUG)
    if not LOOPBACK_ONLY:
        for url in _lan_urls(PORT):
            log.info("  reachable on this network at %s", url)

    app.run(host=HOST, port=PORT, debug=DEBUG, use_reloader=USE_RELOADER)
