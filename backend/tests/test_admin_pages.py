"""
Functional tests for the now-editable admin pages (user management + settings).

Covers the happy paths, the validation, the self-lockout guards, and that user
input is escaped on output (defence in depth).
"""
from werkzeug.security import check_password_hash

from data import repos
from conftest import PASSWORDS

CSRF = {"_csrf_token": "test-csrf-token"}


# ===========================================================================
# User management
# ===========================================================================
def test_admin_can_create_user(client, seeded_db, login):
    login(client, "admin")
    resp = client.post("/admin/users/create", data={
        **CSRF, "username": "newbie", "full_name": "New B.",
        "role": "monitor", "password": "s3cret-pass", "confirm_password": "s3cret-pass"})
    assert resp.status_code == 302
    u = repos.get_user_by_username("newbie")
    assert u is not None and u["role"] == "monitor" and u["is_active"] == 1
    assert check_password_hash(u["password_hash"], "s3cret-pass")


def test_create_user_rejects_short_password(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/users/create", data={
        **CSRF, "username": "shorty", "role": "viewer",
        "password": "short", "confirm_password": "short"})
    assert repos.get_user_by_username("shorty") is None      # not created


def test_create_user_rejects_duplicate_username(client, seeded_db, login):
    login(client, "admin")
    before = len(repos.list_users())
    client.post("/admin/users/create", data={
        **CSRF, "username": "viewer", "role": "viewer",
        "password": "another-pass", "confirm_password": "another-pass"})
    assert len(repos.list_users()) == before                 # no dup row


def test_admin_can_change_role(client, seeded_db, login):
    login(client, "admin")
    vid = seeded_db["users"]["viewer"]
    resp = client.post(f"/admin/users/{vid}/role", data={**CSRF, "role": "monitor"})
    assert resp.status_code == 302
    assert repos.get_user_by_id(vid)["role"] == "monitor"


def test_admin_can_disable_and_enable_user(client, seeded_db, login):
    login(client, "admin")
    vid = seeded_db["users"]["viewer"]
    client.post(f"/admin/users/{vid}/active", data={**CSRF, "active": "0"})
    assert repos.get_user_by_id(vid)["is_active"] == 0
    client.post(f"/admin/users/{vid}/active", data={**CSRF, "active": "1"})
    assert repos.get_user_by_id(vid)["is_active"] == 1


def test_admin_can_reset_password(client, seeded_db, login):
    login(client, "admin")
    vid = seeded_db["users"]["viewer"]
    client.post(f"/admin/users/{vid}/password", data={
        **CSRF, "password": "brand-new-pass", "confirm_password": "brand-new-pass"})
    h = repos.get_user_by_id(vid)["password_hash"]
    assert check_password_hash(h, "brand-new-pass")
    assert not check_password_hash(h, PASSWORDS["viewer"])    # old one no longer works


# --- self-lockout guards -----------------------------------------------------
def test_admin_cannot_disable_own_account(client, seeded_db, login):
    login(client, "admin")
    aid = seeded_db["users"]["admin"]
    client.post(f"/admin/users/{aid}/active", data={**CSRF, "active": "0"})
    assert repos.get_user_by_id(aid)["is_active"] == 1        # still active


def test_admin_cannot_demote_own_role(client, seeded_db, login):
    login(client, "admin")
    aid = seeded_db["users"]["admin"]
    client.post(f"/admin/users/{aid}/role", data={**CSRF, "role": "viewer"})
    assert repos.get_user_by_id(aid)["role"] == "admin"       # unchanged


def test_cannot_demote_last_active_admin(client, seeded_db, login):
    """Even a *different* admin can't be demoted if they are the last one."""
    login(client, "admin")
    aid = seeded_db["users"]["admin"]
    # Create a second admin, log in as them, then try to demote the original.
    client.post("/admin/users/create", data={
        **CSRF, "username": "admin2", "role": "admin",
        "password": "admin2-pass", "confirm_password": "admin2-pass"})
    a2 = repos.get_user_by_username("admin2")["id"]
    # Disable admin2 so only the original admin is an ACTIVE admin again...
    client.post(f"/admin/users/{a2}/active", data={**CSRF, "active": "0"})
    # ...now demoting the original (last active admin) must be refused.
    client.post(f"/admin/users/{aid}/role", data={**CSRF, "role": "monitor"})
    assert repos.get_user_by_id(aid)["role"] == "admin"


def test_username_is_escaped_on_users_page(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/users/create", data={
        **CSRF, "username": "<b>x</b>", "role": "viewer",
        "password": "escape-me-pass", "confirm_password": "escape-me-pass"})
    resp = client.get("/admin/users")
    assert b"<b>x</b>" not in resp.data
    assert b"&lt;b&gt;x&lt;/b&gt;" in resp.data


# ===========================================================================
# Detection settings
# ===========================================================================
def test_settings_page_renders_editable_form(client, seeded_db, login):
    login(client, "admin")
    resp = client.get("/admin/settings")
    assert resp.status_code == 200
    assert b'name="scan_interval_seconds"' in resp.data       # an input, not text
    assert b"Save settings" in resp.data


def test_admin_can_save_valid_settings(client, seeded_db, login):
    login(client, "admin")
    resp = client.post("/admin/settings", data={
        **CSRF,
        "scan_interval_seconds": "45",
        "offline_after_missed": "5",
        "portscan_port_threshold": "20",
        "portscan_window_seconds": "90",
        "quiet_hours_start": "01:00",
        "quiet_hours_end": "06:00",
        "monitor_interface": "Wi-Fi",
        "monitor_subnet": "192.168.5.0/24",
    })
    assert resp.status_code == 302
    assert repos.get_int_setting("scan_interval_seconds", 0) == 45
    assert repos.get_int_setting("offline_after_missed", 0) == 5
    assert repos.get_setting("monitor_subnet") == "192.168.5.0/24"
    assert repos.get_setting("quiet_hours_start") == "01:00"


def test_settings_rejects_bad_int(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={
        **CSRF, "scan_interval_seconds": "not-a-number"})
    # Rejected -> unchanged from the seeded default.
    assert repos.get_int_setting("scan_interval_seconds", 0) == 60


def test_settings_rejects_below_minimum(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={**CSRF, "scan_interval_seconds": "1"})
    assert repos.get_int_setting("scan_interval_seconds", 0) == 60   # min is 5


def test_settings_rejects_bad_cidr(client, seeded_db, login):
    login(client, "admin")
    repos.set_setting("monitor_subnet", "192.168.1.0/24")
    client.post("/admin/settings", data={**CSRF, "monitor_subnet": "not-a-subnet"})
    assert repos.get_setting("monitor_subnet") == "192.168.1.0/24"   # unchanged


def test_settings_rejects_bad_time(client, seeded_db, login):
    login(client, "admin")
    client.post("/admin/settings", data={**CSRF, "quiet_hours_start": "25:99"})
    assert repos.get_setting("quiet_hours_start") == "00:00"         # unchanged
