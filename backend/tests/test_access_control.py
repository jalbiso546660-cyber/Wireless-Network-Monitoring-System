"""
Table-driven access-control tests.

One ROW per protected route. For every (route x role) we assert the exact
status. Adding a route = adding a row.

Expected-status rule (encodes the app's RBAC contract):
  * anonymous            -> 302 (redirected to /login) for EVERY protected route;
  * role IS allowed      -> 200 for GET, 302 for a POST action (redirect/So);
  * role NOT allowed      -> 403 Forbidden (route-level, not just a hidden link).

CSRF is armed on every client (including anonymous) so this file measures the
ACCESS-CONTROL dimension in isolation; CSRF is tested separately in
test_security.py.
"""
import pytest

# Allowed-role sets (admin is a superuser and is added implicitly below).
LOGIN_ONLY = {"viewer", "monitor", "admin"}   # any authenticated user
MONITOR_UP = {"monitor", "admin"}
ADMIN_ONLY = {"admin"}

ROLES = ["anon", "viewer", "monitor", "admin"]


def _routes(device_id, user_id, alert_id):
    """(method, path, allowed_roles). ids already substituted."""
    return [
        ("GET",  "/",                                  LOGIN_ONLY),
        ("GET",  "/dashboard",                         LOGIN_ONLY),
        ("GET",  "/devices",                           LOGIN_ONLY),
        ("GET",  f"/devices/{device_id}",              LOGIN_ONLY),
        ("GET",  "/alerts",                            LOGIN_ONLY),
        ("GET",  f"/alerts/{alert_id}",                LOGIN_ONLY),
        ("GET",  "/reports",                           LOGIN_ONLY),
        ("GET",  "/reports/devices.csv",               MONITOR_UP),   # export = Admin+Monitor
        ("GET",  "/api/devices",                       LOGIN_ONLY),
        ("GET",  "/api/summary",                       LOGIN_ONLY),
        ("GET",  "/api/charts/occupancy",              LOGIN_ONLY),
        ("GET",  "/api/charts/alerts-by-severity",     LOGIN_ONLY),
        ("GET",  "/api/charts/alerts-over-time",       LOGIN_ONLY),
        ("GET",  "/api/charts/alerts-by-rule",         LOGIN_ONLY),
        ("GET",  "/api/charts/device-status",          LOGIN_ONLY),
        ("GET",  "/api/charts/vendor-distribution",    LOGIN_ONLY),
        ("GET",  "/api/charts/scan-history",           LOGIN_ONLY),
        ("GET",  "/api/charts/presence-timeline",      LOGIN_ONLY),
        ("GET",  "/activity",                          LOGIN_ONLY),
        ("GET",  "/account/password",                  LOGIN_ONLY),
        ("POST", "/account/password",                  LOGIN_ONLY),
        ("GET",  "/admin/users",                       ADMIN_ONLY),
        ("GET",  "/admin/settings",                    ADMIN_ONLY),
        ("POST", "/scan/now",                          MONITOR_UP),
        ("POST", f"/alerts/{alert_id}/ack",            MONITOR_UP),
        ("POST", f"/alerts/{alert_id}/resolve",        MONITOR_UP),
        ("POST", f"/devices/{device_id}/authorize",    ADMIN_ONLY),
        ("POST", f"/devices/{device_id}/block",        ADMIN_ONLY),
        ("POST", f"/devices/{device_id}/label",        ADMIN_ONLY),
        ("POST", f"/devices/{device_id}/merge",        ADMIN_ONLY),
        ("POST", "/admin/users/create",                ADMIN_ONLY),
        ("POST", f"/admin/users/{user_id}/role",       ADMIN_ONLY),
        ("POST", f"/admin/users/{user_id}/active",     ADMIN_ONLY),
        ("POST", f"/admin/users/{user_id}/password",   ADMIN_ONLY),
        ("POST", "/admin/settings",                    ADMIN_ONLY),
        ("POST", "/admin/settings/interface",          ADMIN_ONLY),
        ("POST", "/admin/settings/reset-baseline",     ADMIN_ONLY),
        ("POST", "/logout",                            LOGIN_ONLY),
    ]


def _expected(method, role, allowed):
    if role == "anon":
        return 302                      # bounced to login
    if role in allowed:
        return 200 if method == "GET" else 302
    return 403                          # authenticated but wrong role


def _make_client(app, login, role):
    c = app.test_client()
    if role == "anon":
        with c.session_transaction() as s:
            s["_csrf_token"] = "test-csrf-token"    # arm CSRF even for anon
    else:
        login(c, role)
    return c


def _send(client, method, path):
    if method == "GET":
        return client.get(path)
    return client.post(path, data={"_csrf_token": "test-csrf-token"})


@pytest.mark.parametrize("role", ROLES)
def test_access_control_matrix(app, seeded_db, login, role):
    device_id = seeded_db["device_id"]
    # Target the seeded 'viewer' for user-mutating routes so admin actions don't
    # hit the self-lockout guard (which would still 302, but keep intent clear).
    user_id = seeded_db["users"]["viewer"]
    alert_id = seeded_db["alert_id"]
    client = _make_client(app, login, role)

    failures = []
    for method, path, allowed in _routes(device_id, user_id, alert_id):
        expected = _expected(method, role, allowed)
        resp = _send(client, method, path)
        if resp.status_code != expected:
            failures.append(
                f"{role:8} {method:4} {path:32} "
                f"expected {expected} got {resp.status_code}")

    assert not failures, "Access-control mismatches:\n" + "\n".join(failures)


def test_wrong_role_is_403_even_for_missing_device(app, seeded_db, login):
    """RBAC is enforced BEFORE the 404 check: a viewer POSTing to an admin
    action on a non-existent device still gets 403, never 404."""
    c = app.test_client()
    login(c, "viewer")
    resp = c.post("/devices/999999/authorize",
                  data={"_csrf_token": "test-csrf-token"})
    assert resp.status_code == 403


def test_admin_action_on_missing_device_is_404(app, seeded_db, login):
    """An ALLOWED role hitting a missing device gets 404 (past the RBAC gate)."""
    c = app.test_client()
    login(c, "admin")
    resp = c.post("/devices/999999/authorize",
                  data={"_csrf_token": "test-csrf-token"})
    assert resp.status_code == 404
