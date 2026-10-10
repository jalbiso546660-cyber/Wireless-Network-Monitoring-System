"""
web/routes/auth.py  — Module 1: User Management & Authentication

The security boundary of the application. Contains:
  * the Flask-Login manager and the User class (loaded from the users table);
  * authenticate() / login / logout / change_password (self-service);
  * the @role_required(*roles) decorator that enforces RBAC on the ROUTE and
    returns 403 — hiding a nav link is NOT the security boundary;
  * a per-IP lockout after repeated failed logins;
  * admin-only account management (create / role / enable-disable / reset).

Passwords are verified with werkzeug.security.check_password_hash; plaintext is
never stored or compared.
"""
from __future__ import annotations

import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from werkzeug.security import check_password_hash, generate_password_hash

from data import repos

auth_bp = Blueprint("auth", __name__)


def _is_safe_next_url(target: str | None) -> bool:
    """True only for a same-site, path-only redirect target. Rejects absolute
    URLs (scheme/host), protocol-relative ``//host``, whitespace, and backslash
    tricks like ``/\\host`` that some browsers normalise to ``//`` and follow
    off-site (the historic open-redirect gap)."""
    if not target:
        return False
    if any(c in target for c in ("\\", "\r", "\n", "\t", " ")):
        return False
    if not target.startswith("/") or target.startswith("//"):
        return False
    parts = urlparse(target)
    return not parts.scheme and not parts.netloc

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"   # ties the session to the client

# Same message for EVERY failure mode so we never reveal whether a username
# exists (defends against username enumeration).
_GENERIC_LOGIN_ERROR = "Invalid username or password."
# A valid hash to check against when the username is unknown, so a failed login
# takes ~the same time whether or not the account exists (timing-oracle defence).
_DUMMY_HASH = generate_password_hash("account-does-not-exist", method="pbkdf2:sha256")

MIN_PASSWORD_LEN = 8
VALID_ROLES = ("admin", "monitor", "viewer")


class User(UserMixin):
    """Adapts a `users` table row to what Flask-Login expects."""

    def __init__(self, row: dict):
        self.id = row["id"]
        self.username = row["username"]
        self.full_name = row.get("full_name")
        self.role = row["role"]
        self.password_hash = row["password_hash"]
        self._active = bool(row["is_active"])

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_active(self) -> bool:
        # Flask-Login refuses to keep a session for an inactive user.
        return self._active

    def has_role(self, *roles: str) -> bool:
        """True if the user has one of `roles`. Admin is a superuser."""
        return self.role == "admin" or self.role in roles


@login_manager.user_loader
def load_user(user_id: str):
    row = repos.get_user_by_id(int(user_id))
    return User(row) if row else None


# ---------------------------------------------------------------------------
# Route-level RBAC — returns 403, never merely hides UI
# ---------------------------------------------------------------------------
def role_required(*roles: str):
    """Require the logged-in user to hold one of `roles` (admin always passes).

    Unauthenticated  -> redirect to login (via Flask-Login's unauthorized).
    Wrong role       -> 403 Forbidden (a viewer typing an admin URL is refused).
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != "admin" and current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Per-IP lockout after repeated failed logins (in-memory; fine for one host)
# ---------------------------------------------------------------------------
_MAX_FAILURES = 5
_LOCKOUT_SECONDS = 300
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


def _client_key() -> str:
    return request.remote_addr or "unknown"


def _is_locked(key: str) -> tuple[bool, int]:
    now = time.time()
    with _lock:
        recent = [t for t in _failures.get(key, []) if now - t < _LOCKOUT_SECONDS]
        _failures[key] = recent
        if len(recent) >= _MAX_FAILURES:
            return True, int(_LOCKOUT_SECONDS - (now - max(recent)))
    return False, 0


def _record_failure(key: str) -> None:
    with _lock:
        _failures.setdefault(key, []).append(time.time())


def _clear_failures(key: str) -> None:
    with _lock:
        _failures.pop(key, None)


# ---------------------------------------------------------------------------
# Credential verification (Module 1.2)
# ---------------------------------------------------------------------------
def authenticate(username: str, password: str) -> "User | None":
    """Verify credentials. Returns a User on success, else None.

    SECURITY: runs exactly one hash check whether or not the username exists
    (a dummy hash for unknown users) so response time never reveals account
    existence; refuses inactive accounts; and never distinguishes the failure
    reason to the caller (defends username enumeration + timing oracles).
    """
    row = repos.get_user_by_username((username or "").strip())
    stored_hash = row["password_hash"] if row else _DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password or "")
    if row and password_ok and bool(row["is_active"]):
        return User(row)
    return None


def change_password(user_id: int, current_password: str,
                    new_password: str) -> tuple[bool, str]:
    """Self-service password change: verify the CURRENT password, enforce a
    minimum length, then store a new pbkdf2 hash. Returns (ok, message)."""
    user = repos.get_user_by_id(user_id)
    if not user:
        return False, "User not found."
    if not check_password_hash(user["password_hash"], current_password or ""):
        return False, "Current password is incorrect."
    if len(new_password or "") < MIN_PASSWORD_LEN:
        return False, f"New password must be at least {MIN_PASSWORD_LEN} characters."
    repos.update_user_password(
        user_id, generate_password_hash(new_password, method="pbkdf2:sha256"))
    return True, "Password changed."


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        key = _client_key()
        locked, remaining = _is_locked(key)
        if locked:
            flash(f"Too many failed attempts. Try again in {remaining} seconds.",
                  "danger")
            return render_template("login.html"), 429

        user = authenticate(request.form.get("username"),
                            request.form.get("password") or "")
        if user:
            _clear_failures(key)
            login_user(user)
            # Open-redirect protection: only follow safe, same-site paths.
            next_url = request.args.get("next")
            if not _is_safe_next_url(next_url):
                next_url = url_for("dashboard.index")
            return redirect(next_url)

        _record_failure(key)
        flash(_GENERIC_LOGIN_ERROR, "danger")     # identical for all failures
        return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])   # POST so logout itself is CSRF-safe
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


def _back_to_referrer_or(fallback_endpoint: str):
    """Redirect to the page the request came from (same-site only), or to
    `fallback_endpoint` if there is no safe referrer. Used so a form opened
    from the change-password MODAL (which can live on any page) returns the
    user to that same page on error, instead of jumping to a standalone page."""
    ref = request.referrer or ""
    parts = urlparse(ref)
    if ref and (not parts.netloc or parts.netloc == request.host):
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        if path.startswith("/") and not path.startswith("//") and "\\" not in path:
            return redirect(path)
    return redirect(url_for(fallback_endpoint))


@auth_bp.route("/account/password", methods=["GET", "POST"])
@login_required
def account_password():
    """Self-service password change for the logged-in user."""
    if request.method == "POST":
        new = request.form.get("new_password") or ""
        if new != (request.form.get("confirm_password") or ""):
            flash("New passwords do not match.", "danger")
            # Same-page-return as every other failure below (the modal can be
            # opened from any page; this used to always jump to the standalone
            # /account/password page instead, breaking that consistency).
            return _back_to_referrer_or("auth.account_password")
        ok, msg = change_password(current_user.id,
                                  request.form.get("current_password"), new)
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("dashboard.index"))
        # Failed: go back to the page the modal was opened from (same-site only)
        # so the error is shown in context; fall back to the standalone page.
        return _back_to_referrer_or("auth.account_password")
    return render_template("change_password.html")


# ---------------------------------------------------------------------------
# Account management — ADMIN ONLY (Module 1.1). Self-lockout guards prevent an
# admin from disabling/demoting their own account or the last active admin.
# ---------------------------------------------------------------------------
@auth_bp.route("/admin/users")
@role_required("admin")
def users():
    return render_template("admin_users.html",
                           users=repos.list_users(), valid_roles=VALID_ROLES)


@auth_bp.route("/admin/users/create", methods=["POST"])
@role_required("admin")
def users_create():
    username = (request.form.get("username") or "").strip()
    full_name = (request.form.get("full_name") or "").strip() or None
    role = (request.form.get("role") or "").strip().lower()
    pw = request.form.get("password") or ""
    pw2 = request.form.get("confirm_password") or ""

    if not username:
        flash("Username is required.", "danger")
    elif repos.get_user_by_username(username):
        flash(f"A user named '{username}' already exists.", "danger")
    elif role not in VALID_ROLES:
        flash(f"Choose a valid role {VALID_ROLES}.", "danger")
    elif len(pw) < MIN_PASSWORD_LEN:
        flash(f"Password must be at least {MIN_PASSWORD_LEN} characters.", "danger")
    elif pw != pw2:
        flash("Passwords do not match.", "danger")
    else:
        repos.create_user(
            username, generate_password_hash(pw, method="pbkdf2:sha256"),
            full_name, role, is_active=True)
        flash(f"User '{username}' created (role={role}).", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def users_role(user_id: int):
    user = repos.get_user_by_id(user_id)
    if not user:
        abort(404)
    new_role = (request.form.get("role") or "").strip().lower()

    if new_role not in VALID_ROLES:
        flash(f"Invalid role. Choose from {VALID_ROLES}.", "danger")
    elif user_id == current_user.id and new_role != "admin":
        flash("You cannot change your own admin role (self-lockout guard).", "danger")
    elif (user["role"] == "admin" and new_role != "admin"
          and repos.count_active_admins() <= 1):
        flash("Refusing to demote the last active admin.", "danger")
    else:
        repos.set_user_role(user_id, new_role)
        flash(f"Role for '{user['username']}' set to {new_role}.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/admin/users/<int:user_id>/active", methods=["POST"])
@role_required("admin")
def users_active(user_id: int):
    user = repos.get_user_by_id(user_id)
    if not user:
        abort(404)
    enable = request.form.get("active") == "1"

    if user_id == current_user.id and not enable:
        flash("You cannot disable your own account.", "danger")
    elif (user["role"] == "admin" and user["is_active"] and not enable
          and repos.count_active_admins() <= 1):
        flash("Refusing to disable the last active admin.", "danger")
    elif enable:
        repos.set_user_active(user_id, True)
        flash(f"User '{user['username']}' enabled.", "success")
    else:
        repos.deactivate_user(user_id)
        flash(f"User '{user['username']}' disabled.", "success")
    return redirect(url_for("auth.users"))


@auth_bp.route("/admin/users/<int:user_id>/password", methods=["POST"])
@role_required("admin")
def users_password(user_id: int):
    user = repos.get_user_by_id(user_id)
    if not user:
        abort(404)
    pw = request.form.get("password") or ""
    pw2 = request.form.get("confirm_password") or ""

    if len(pw) < MIN_PASSWORD_LEN:
        flash(f"Password must be at least {MIN_PASSWORD_LEN} characters.", "danger")
    elif pw != pw2:
        flash("Passwords do not match.", "danger")
    else:
        repos.update_user_password(
            user_id, generate_password_hash(pw, method="pbkdf2:sha256"))
        flash(f"Password reset for '{user['username']}'.", "success")
    return redirect(url_for("auth.users"))
