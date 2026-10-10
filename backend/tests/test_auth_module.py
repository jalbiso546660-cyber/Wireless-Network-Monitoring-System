"""
Module 1 — User Management & Authentication: authenticate(), change_password(),
deactivate_user(), and the self-service password route.
"""
from werkzeug.security import check_password_hash

from data import repos
from web.routes import auth
from conftest import PASSWORDS

CSRF = {"_csrf_token": "test-csrf-token"}


# --- authenticate ------------------------------------------------------------
def test_authenticate_success_returns_user(seeded_db):
    user = auth.authenticate("admin", PASSWORDS["admin"])
    assert user is not None and user.role == "admin"


def test_authenticate_wrong_password_is_none(seeded_db):
    assert auth.authenticate("admin", "wrong") is None


def test_authenticate_unknown_user_is_none(seeded_db):
    # No exception, no timing tell — just None.
    assert auth.authenticate("nobody", "whatever") is None


def test_authenticate_inactive_user_is_none(seeded_db):
    row = repos.get_user_by_username("viewer")
    repos.deactivate_user(row["id"])
    assert auth.authenticate("viewer", PASSWORDS["viewer"]) is None


# --- deactivate_user ---------------------------------------------------------
def test_deactivate_user(seeded_db):
    row = repos.get_user_by_username("monitor")
    repos.deactivate_user(row["id"])
    assert repos.get_user_by_id(row["id"])["is_active"] == 0
    # audit row preserved (not deleted).
    assert repos.get_user_by_username("monitor") is not None


# --- change_password (verifies current) -------------------------------------
def test_change_password_requires_correct_current(seeded_db):
    uid = repos.get_user_by_username("admin")["id"]
    ok, msg = auth.change_password(uid, "wrong-current", "brand-new-pass")
    assert ok is False and "incorrect" in msg.lower()
    # unchanged: old password still verifies.
    assert check_password_hash(repos.get_user_by_id(uid)["password_hash"],
                               PASSWORDS["admin"])


def test_change_password_enforces_min_length(seeded_db):
    uid = repos.get_user_by_username("admin")["id"]
    ok, _ = auth.change_password(uid, PASSWORDS["admin"], "short")
    assert ok is False


def test_change_password_success(seeded_db):
    uid = repos.get_user_by_username("admin")["id"]
    ok, _ = auth.change_password(uid, PASSWORDS["admin"], "a-fresh-password")
    assert ok is True
    h = repos.get_user_by_id(uid)["password_hash"]
    assert check_password_hash(h, "a-fresh-password")
    assert not check_password_hash(h, PASSWORDS["admin"])


# --- self-service route ------------------------------------------------------
def test_account_password_route_changes_own_password(client, seeded_db, login):
    login(client, "viewer")
    resp = client.post("/account/password", data={
        **CSRF, "current_password": PASSWORDS["viewer"],
        "new_password": "viewer-new-pass", "confirm_password": "viewer-new-pass"})
    assert resp.status_code == 302
    uid = repos.get_user_by_username("viewer")["id"]
    assert check_password_hash(repos.get_user_by_id(uid)["password_hash"],
                               "viewer-new-pass")


def test_account_password_rejects_mismatch(client, seeded_db, login):
    login(client, "viewer")
    resp = client.post("/account/password", data={
        **CSRF, "current_password": PASSWORDS["viewer"],
        "new_password": "aaaaaaaa", "confirm_password": "bbbbbbbb"})
    assert resp.status_code == 302        # redirected back with a flash
    uid = repos.get_user_by_username("viewer")["id"]
    assert check_password_hash(repos.get_user_by_id(uid)["password_hash"],
                               PASSWORDS["viewer"])     # unchanged


def test_account_password_page_renders(client, seeded_db, login):
    login(client, "monitor")
    resp = client.get("/account/password")
    assert resp.status_code == 200
    assert b"Change password" in resp.data


def test_account_password_mismatch_returns_to_the_calling_page(client, seeded_db, login):
    """Regression: a password-confirm mismatch used to always redirect to the
    standalone /account/password page, unlike every other failure in this
    route (wrong current password, too short), which return to the page the
    modal was opened from. Both must behave the same way."""
    login(client, "viewer")
    resp = client.post("/account/password", data={
        "_csrf_token": "test-csrf-token", "current_password": PASSWORDS["viewer"],
        "new_password": "aaaaaaaa", "confirm_password": "bbbbbbbb"},
        headers={"Referer": "http://localhost/alerts?status=new"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/alerts?status=new")
