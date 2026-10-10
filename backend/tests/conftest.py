"""
tests/conftest.py
=================
Shared pytest fixtures for the PWNM test suite.

SAFETY: these tests NEVER touch your real `pwnm` database.

  * Before any project module is imported, we force DB_NAME to `pwnm_test`
    (python-dotenv's load_dotenv does NOT override an already-set env var, so
    this wins over .env). We also pin a throwaway SECRET_KEY so the suite does
    not depend on your .env secret.
  * A separate `pwnm_test` schema is created from sql/schema.sql's table DDL,
    seeded to a known state before every DB test, and DROPPED at the end.
  * A hard assert refuses to run any destructive statement unless the target
    database name ends in `_test`.

Fixtures
--------
  test_database   (session)  create pwnm_test once; drop it at the end.
  seeded_db       (function) truncate + reseed to a known state; hand back the
                             seeded ids. Request this in any DB test.
  app / client    (function) a Flask app + test client on the reset DB.
  login           (helper)   log a client in as a seeded role and arm CSRF.
"""
from __future__ import annotations

import os
import sys

# --- 1. Point the whole app at the TEST database BEFORE importing config -----
os.environ["DB_NAME"] = "pwnm_test"
os.environ.setdefault("SECRET_KEY", "test-only-secret-not-a-real-deployment-key")

# Make `import config`, `import app`, `from data import db` resolve from root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import mysql.connector  # noqa: E402
import pytest  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

import config  # noqa: E402  (now bound to pwnm_test)
from data import db  # noqa: E402

TEST_DB = config.DB_NAME
assert TEST_DB.endswith("_test"), (
    f"Refusing to run: test DB name is {TEST_DB!r}, which does not end in "
    f"'_test'. The suite must never point at your real database.")

SCHEMA_PATH = os.path.join(_ROOT, "sql", "schema.sql")

# Known seed credentials — deterministic, independent of your real users.
PASSWORDS = {
    "admin": "admin-pass-123",
    "monitor": "monitor-pass-123",
    "viewer": "viewer-pass-123",
}

SEED_DEVICE_MAC = "aa:bb:cc:dd:ee:01"
SEED_DEVICE_IP = "192.168.1.50"


# ---------------------------------------------------------------------------
# Low-level helpers (use a dedicated connection, NOT the app's pool)
# ---------------------------------------------------------------------------
def _admin_conn(with_db: bool):
    """A plain connector connection for setup/teardown DDL."""
    return mysql.connector.connect(**config.Config.db_params(include_database=with_db))


def _table_ddl_statements() -> list[str]:
    """Extract just the CREATE TABLE statements from schema.sql.

    We deliberately skip the file's DROP DATABASE/CREATE DATABASE/USE header
    (which is hard-coded to `pwnm`) and its seed INSERTs — the test suite seeds
    its own known state per test.
    """
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        raw = f.read()
    # Strip -- line comments so naive ';' splitting is safe.
    lines = [ln for ln in raw.splitlines() if not ln.lstrip().startswith("--")]
    body = "\n".join(lines)
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    return [s for s in stmts if s.upper().startswith("CREATE TABLE")]


def _create_test_database() -> None:
    conn = _admin_conn(with_db=False)
    try:
        cur = conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
        cur.execute(
            f"CREATE DATABASE {TEST_DB} CHARACTER SET utf8mb4 "
            f"COLLATE utf8mb4_unicode_ci")
        cur.execute(f"USE {TEST_DB}")
        for ddl in _table_ddl_statements():
            cur.execute(ddl)
        conn.commit()
        cur.close()
    finally:
        conn.close()


def _drop_test_database() -> None:
    conn = _admin_conn(with_db=False)
    try:
        cur = conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB}")
        conn.commit()
        cur.close()
    finally:
        conn.close()


# The 6 seed settings that ship in schema.sql (thresholds live in the DB).
_SEED_SETTINGS = [
    ("scan_interval_seconds", "60"),
    ("profile_interval_seconds", "300"),
    ("offline_after_missed", "3"),
    ("portscan_port_threshold", "15"),
    ("portscan_window_seconds", "60"),
    ("quiet_hours_start", "00:00"),
    ("quiet_hours_end", "05:00"),
    ("unauth_return_rate_limit_seconds", "3600"),
    ("alert_dedup_seconds", "300"),
    ("ipchurn_distinct_ips", "3"),
    ("ipchurn_window_minutes", "10"),
    ("arp_conflict_window_seconds", "120"),
    ("service_watch_ports", "22,23,21,445,3389,5900,3306,1433"),
    ("log_retention_days", "90"),
    # Added at runtime by the scheduler in the real app; seeded here so the
    # settings editor has them to edit.
    ("monitor_interface", "Wi-Fi"),
    ("monitor_subnet", "192.168.1.0/24"),
]


def _reset_and_seed() -> dict:
    """Truncate every table and reseed a known state. Returns seeded ids.

    Runs on a dedicated connection and commits, so the app's pool sees the
    committed state on its next borrow.
    """
    conn = _admin_conn(with_db=True)
    try:
        cur = conn.cursor()
        cur.execute("SET FOREIGN_KEY_CHECKS = 0")
        for t in ("access_logs", "alerts", "scan_sessions", "setting_audit",
                  "devices", "users", "settings"):
            cur.execute(f"TRUNCATE TABLE {t}")
        cur.execute("SET FOREIGN_KEY_CHECKS = 1")

        cur.executemany(
            "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)",
            _SEED_SETTINGS)

        user_ids = {}
        for username, role in (("admin", "admin"), ("monitor", "monitor"),
                               ("viewer", "viewer")):
            cur.execute(
                "INSERT INTO users (username, password_hash, full_name, role, "
                "is_active) VALUES (%s, %s, %s, %s, 1)",
                (username,
                 generate_password_hash(PASSWORDS[username], method="pbkdf2:sha256"),
                 username.title(), role))
            user_ids[username] = cur.lastrowid

        cur.execute(
            "INSERT INTO devices (mac_address, last_ip, hostname, vendor, "
            "status, is_online) VALUES (%s, %s, %s, %s, 'unauthorized', 1)",
            (SEED_DEVICE_MAC, SEED_DEVICE_IP, "seed-host", "SeedVendor"))
        device_id = cur.lastrowid

        cur.execute(
            "INSERT INTO alerts (device_id, rule_code, severity, title, detail) "
            "VALUES (%s, 'NEW_DEVICE', 'low', %s, %s)",
            (device_id, "Seed alert", "seeded for tests"))
        alert_id = cur.lastrowid

        conn.commit()
        cur.close()
        return {"users": user_ids, "device_id": device_id, "alert_id": alert_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def test_database():
    """Create pwnm_test once for the whole run; drop it at the end."""
    try:
        _create_test_database()
    except mysql.connector.Error as e:
        pytest.skip(f"MySQL not available for integration tests: {e}")
    # Reset the app pool so it binds fresh to the freshly-created DB.
    db._pool = None
    yield
    _drop_test_database()


@pytest.fixture
def seeded_db(test_database):
    """Reset to known state before the test; hand back the seeded ids."""
    ids = _reset_and_seed()
    yield ids


@pytest.fixture
def app(seeded_db):
    """A Flask app wired to the reset test DB, in non-debug testing mode."""
    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)
    flask_app._seeded = seeded_db
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def project_root():
    """Absolute path to the project root (for source-inspection tests)."""
    return _ROOT


@pytest.fixture
def login():
    """Return a helper: login(client, username) -> csrf_token.

    Performs a real login (exercising the auth path), then pins a known CSRF
    token in the session so state-changing POSTs in the test can pass the
    global CSRF check.
    """
    def _login(client, username: str) -> str:
        # GET first so a session cookie exists, then POST real credentials.
        client.get("/login")
        with client.session_transaction() as sess:
            sess["_csrf_token"] = "test-csrf-token"
        resp = client.post("/login", data={
            "username": username,
            "password": PASSWORDS[username],
            "_csrf_token": "test-csrf-token",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303), (
            f"login for {username} failed: {resp.status_code}")
        # Re-pin CSRF (login may have rotated the session).
        with client.session_transaction() as sess:
            sess["_csrf_token"] = "test-csrf-token"
        return "test-csrf-token"
    return _login
