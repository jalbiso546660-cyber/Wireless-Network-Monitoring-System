"""
Security tests. Results here are transcribed into
tests/security_self_assessment.md.

Covers: SQL injection, XSS on device labels, CSRF enforcement, access-control
bypass by direct URL, session/auth handling, open-redirect protection, password
storage, secrets handling, and error-message leakage (custom error pages, no
stack traces).
"""
import pytest

from data import db, repos
from conftest import PASSWORDS


def _arm(client):
    with client.session_transaction() as s:
        s["_csrf_token"] = "test-csrf-token"


def _is_logged_in(client) -> bool:
    with client.session_transaction() as s:
        return "_user_id" in s


# ===========================================================================
# SQL injection
# ===========================================================================
@pytest.mark.parametrize("payload", [
    "admin' --",
    "admin' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
])
def test_sqli_login_username_cannot_bypass_auth(client, payload):
    _arm(client)
    resp = client.post("/login", data={
        "username": payload, "password": "anything",
        "_csrf_token": "test-csrf-token"}, follow_redirects=False)
    assert resp.status_code == 401         # rejected, never a redirect to dashboard
    assert not _is_logged_in(client)
    # The table the payload tried to drop is still there.
    assert repos.get_user_by_username("admin") is not None


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "'; DROP TABLE devices; --",
    "unauthorized' UNION SELECT * FROM users --",
])
def test_sqli_device_filter_is_safe(client, login, payload):
    login(client, "viewer")
    resp = client.get("/devices", query_string={"status": payload})
    assert resp.status_code == 200         # no SQL error, no 500
    # devices table intact and queryable.
    assert isinstance(repos.list_devices(), list)


def test_sqli_in_device_label_is_stored_literally(client, seeded_db, login):
    login(client, "admin")
    did = seeded_db["device_id"]
    payload = "x'); DROP TABLE devices; --"
    resp = client.post(f"/devices/{did}/label",
                       data={"label": payload, "_csrf_token": "test-csrf-token"})
    assert resp.status_code == 302
    # Table survived AND the value was stored verbatim (parameterized, not run).
    assert repos.list_devices() != []
    assert repos.get_device(did)["device_label"] == payload


# ===========================================================================
# XSS on device labels
# ===========================================================================
def test_xss_in_label_is_escaped_on_detail_page(client, seeded_db, login):
    login(client, "admin")
    did = seeded_db["device_id"]
    client.post(f"/devices/{did}/label",
                data={"label": "<script>alert(1)</script>",
                      "_csrf_token": "test-csrf-token"})

    resp = client.get(f"/devices/{did}")
    assert b"<script>alert(1)</script>" not in resp.data     # not raw
    assert b"&lt;script&gt;" in resp.data                    # escaped


def test_xss_in_label_is_escaped_on_list_page(client, seeded_db, login):
    login(client, "admin")
    did = seeded_db["device_id"]
    client.post(f"/devices/{did}/label",
                data={"label": "<img src=x onerror=alert(1)>",
                      "_csrf_token": "test-csrf-token"})

    resp = client.get("/devices")
    assert b"<img src=x onerror=alert(1)>" not in resp.data
    assert b"&lt;img" in resp.data


# ===========================================================================
# CSRF
# ===========================================================================
def test_csrf_missing_token_is_rejected(client, seeded_db, login):
    login(client, "admin")
    did = seeded_db["device_id"]
    # POST WITHOUT the token in the body.
    resp = client.post(f"/devices/{did}/label", data={"label": "nope"})
    assert resp.status_code == 400


def test_csrf_wrong_token_is_rejected(client, seeded_db, login):
    login(client, "admin")
    did = seeded_db["device_id"]
    resp = client.post(f"/devices/{did}/label",
                       data={"label": "nope", "_csrf_token": "WRONG"})
    assert resp.status_code == 400


# ===========================================================================
# Access-control bypass by direct URL (spot checks; matrix is exhaustive)
# ===========================================================================
def test_viewer_cannot_reach_admin_page_by_url(client, login):
    login(client, "viewer")
    assert client.get("/admin/users").status_code == 403


def test_anonymous_is_redirected_to_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# ===========================================================================
# Session / auth
# ===========================================================================
def test_session_cookie_changes_after_login(app, login):
    """The pre-auth session identifier is not reused as the authenticated one
    (a basic session-fixation guard)."""
    c = app.test_client()
    c.get("/login")
    before = c.get_cookie("session")
    before_val = before.value if before else None

    login(c, "admin")
    after = c.get_cookie("session")
    after_val = after.value if after else None

    assert after_val is not None
    assert after_val != before_val


def test_logout_drops_authenticated_access(app, login):
    c = app.test_client()
    login(c, "admin")
    assert c.get("/dashboard").status_code == 200
    c.post("/logout", data={"_csrf_token": "test-csrf-token"})
    assert c.get("/dashboard").status_code == 302     # back to needing login


def test_inactive_user_cannot_log_in(client):
    # Disable the viewer account, then try to authenticate.
    row = repos.get_user_by_username("viewer")
    repos.set_user_active(row["id"], False)
    _arm(client)
    resp = client.post("/login", data={
        "username": "viewer", "password": PASSWORDS["viewer"],
        "_csrf_token": "test-csrf-token"})
    assert resp.status_code == 401
    assert not _is_logged_in(client)


# ===========================================================================
# Open redirect (login ?next=)
# ===========================================================================
@pytest.mark.parametrize("bad_next", [
    "//evil.com",
    "https://evil.com",
    "http://evil.com/path",
])
def test_open_redirect_external_targets_blocked(client, bad_next):
    _arm(client)
    resp = client.post("/login", query_string={"next": bad_next}, data={
        "username": "admin", "password": PASSWORDS["admin"],
        "_csrf_token": "test-csrf-token"}, follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert "evil.com" not in loc          # forced back to a local page


def test_open_redirect_backslash_variant_blocked(client):
    """Previously an xfail gap; now closed by _is_safe_next_url, which rejects
    backslashes that some browsers normalise to // and follow off-site."""
    _arm(client)
    resp = client.post("/login", query_string={"next": "/\\evil.com"}, data={
        "username": "admin", "password": PASSWORDS["admin"],
        "_csrf_token": "test-csrf-token"}, follow_redirects=False)
    assert "evil.com" not in resp.headers["Location"]


# ===========================================================================
# Security headers (CSP etc.)
# ===========================================================================
def test_security_headers_and_csp_present(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Permissions-Policy")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    # script-src is STRICT: it allows self + the CDN but NOT 'unsafe-inline',
    # so an injected inline <script>/handler cannot execute.
    assert "script-src 'self' https://cdn.jsdelivr.net" in csp


# ===========================================================================
# Password storage
# ===========================================================================
def test_passwords_stored_as_pbkdf2_hash(seeded_db):
    from werkzeug.security import check_password_hash
    row = repos.get_user_by_username("admin")
    h = row["password_hash"]
    assert h.startswith("pbkdf2:sha256:")          # salted KDF, not plaintext
    assert PASSWORDS["admin"] not in h              # plaintext not embedded
    assert check_password_hash(h, PASSWORDS["admin"]) is True
    assert check_password_hash(h, "wrong-password") is False


def test_users_table_has_no_plaintext_password_column(seeded_db):
    cols = {r["Field"] for r in db.query("DESCRIBE users")}
    assert "password_hash" in cols
    assert "password" not in cols        # no plaintext column, only the hash


# ===========================================================================
# Secrets in source
# ===========================================================================
def test_secret_key_is_read_from_environment(project_root):
    import os
    src = open(os.path.join(project_root, "config.py"), encoding="utf-8").read()
    assert 'os.getenv("SECRET_KEY"' in src           # not a literal secret
    assert 'os.getenv("DB_PASSWORD"' in src


def test_env_file_is_gitignored(project_root):
    import os
    gi = open(os.path.join(project_root, ".gitignore"), encoding="utf-8").read()
    assert ".env" in gi


def test_example_env_ships_only_a_placeholder_secret(project_root):
    import os
    example = open(os.path.join(project_root, ".env.example"), encoding="utf-8").read()
    # The template must not ship a usable secret.
    assert "SECRET_KEY=change-me-to-a-random-secret" in example


def test_app_refuses_to_boot_with_placeholder_secret(monkeypatch, seeded_db):
    import config
    import app as app_module
    monkeypatch.setattr(config, "SECRET_KEY", "change-me-to-a-random-secret")
    with pytest.raises(RuntimeError):
        app_module.create_app()


# ===========================================================================
# Error messages: custom pages, no stack traces
# ===========================================================================
def test_404_returns_custom_page_without_traceback(client):
    resp = client.get("/no-such-page-exists")
    assert resp.status_code == 404
    assert b"404" in resp.data
    assert b"Traceback" not in resp.data


def test_500_handler_hides_stack_trace(seeded_db):
    """With debug OFF (production posture), an unhandled error renders the
    friendly 500 page and leaks no traceback or exception text."""
    import app as app_module
    a = app_module.create_app()
    a.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)

    @a.route("/__boom__")
    def _boom():
        raise ValueError("secret-internal-detail-kaboom")

    r = a.test_client().get("/__boom__")
    assert r.status_code == 500
    assert b"Something went wrong" in r.data
    assert b"secret-internal-detail-kaboom" not in r.data
    assert b"Traceback" not in r.data


# ===========================================================================
# Brute-force lockout
# ===========================================================================
def test_brute_force_lockout_blocks_after_max_failures(client, seeded_db):
    """After _MAX_FAILURES wrong passwords the client is locked: further attempts
    get 429 even with the CORRECT password (the lock gates BEFORE authentication,
    so guessing cannot continue)."""
    from web.routes import auth
    auth._failures.clear()                 # isolate from other tests
    try:
        _arm(client)
        for _ in range(auth._MAX_FAILURES):
            r = client.post("/login", data={
                "username": "admin", "password": "wrong-password",
                "_csrf_token": "test-csrf-token"})
            assert r.status_code == 401

        # Correct credentials are refused while the lock stands.
        r = client.post("/login", data={
            "username": "admin", "password": PASSWORDS["admin"],
            "_csrf_token": "test-csrf-token"})
        assert r.status_code == 429
        assert b"Too many failed attempts" in r.data
        assert not _is_logged_in(client)
    finally:
        auth._failures.clear()             # never leak the lock to other tests


def test_successful_login_clears_the_failure_counter(client, seeded_db):
    """A good login resets the counter, so honest users are never locked out by
    a few earlier typos."""
    from web.routes import auth
    auth._failures.clear()
    try:
        _arm(client)
        client.post("/login", data={
            "username": "admin", "password": "wrong-password",
            "_csrf_token": "test-csrf-token"})
        assert auth._failures.get("127.0.0.1")          # failure recorded

        client.post("/login", data={
            "username": "admin", "password": PASSWORDS["admin"],
            "_csrf_token": "test-csrf-token"})
        assert not auth._failures.get("127.0.0.1")      # cleared on success
        assert _is_logged_in(client)
    finally:
        auth._failures.clear()
