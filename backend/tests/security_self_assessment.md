# PWNM — Security Self-Assessment

Date: 2026-08-23 · Scope: PWNM web app + data layer (this repository).
Method: automated tests in `tests/test_security.py` (run against an isolated
`pwnm_test` schema) plus live inspection of the running dev server. Every result
below is **actual**, not aspirational.

Result legend: **PASS** = defence present and verified · **PARTIAL** = works but
has a caveat to fix before production · **FAIL** = exploitable now · **N/A**.

| # | Check | How it was tested | Result | Evidence / notes |
|---|-------|-------------------|--------|------------------|
| 1 | **SQL injection** — every input | Injection payloads on the login username, the `/devices?status=` filter, and the device-label POST (`' OR '1'='1`, `'; DROP TABLE …; --`, `UNION SELECT`). | **PASS** | All SQL runs through `data/db.py` helpers with a separate params tuple — no string-built SQL. Payloads were stored/handled literally; login stayed 401; `users`/`devices` tables intact. Tests: `test_sqli_*`. |
| 2 | **XSS** — device labels | Set label to `<script>alert(1)</script>` and `<img src=x onerror=…>`, then rendered the detail and list pages. | **PASS** | Jinja autoescaping is on (and asserted at boot in `app.py`); output came back as `&lt;script&gt;`. Live dashboard uses `textContent` in `live.js`, so JSON-fed values can't inject HTML. Tests: `test_xss_*`. |
| 3 | **XSS** — device notes | Reviewed all routes/templates for a notes input. | **N/A (no input path)** | The `notes` column exists in the schema but **no route or form writes or renders it** yet. Nothing to exploit today; when a notes editor is added it must render through Jinja (autoescaped) like labels. |
| 4 | **Access-control bypass by direct URL** | Table-driven matrix of every protected route × every role, plus direct-URL spot checks. | **PASS** | Enforced at the **route** via `@login_required` / `@role_required` (returns 403), not by hiding links. Wrong role = 403 even before the 404 check. Tests: `test_access_control_matrix`, `test_viewer_cannot_reach_admin_page_by_url`. |
| 5 | **Session fixation / session security** | Compared the `session` cookie before vs after login; inspected cookie flags on the live server. | **PARTIAL** | Cookie value **rotates on login** (verified); Flask-Login `session_protection="strong"`; cookie is `HttpOnly; SameSite=Lax`. **Caveat:** `SESSION_COOKIE_SECURE=False` (set in `app.py`) — over HTTPS this must be `True` or the cookie can leak on a plaintext request. Tests: `test_session_cookie_changes_after_login`, `test_logout_drops_authenticated_access`. |
| 6 | **Password storage** | Inspected stored hashes and the users table columns; round-tripped verify. | **PASS** | Passwords stored as `pbkdf2:sha256:…` (werkzeug), salted, one-way. No plaintext `password` column — only `password_hash`. Correct password verifies, wrong one fails. Tests: `test_passwords_stored_as_pbkdf2_hash`, `test_users_table_has_no_plaintext_password_column`. |
| 7 | **Secrets in source** | Read `config.py`, `.gitignore`, `.env.example`; forced a placeholder secret through `create_app()`. | **PASS** | `SECRET_KEY` and `DB_PASSWORD` come from environment (`os.getenv`), not literals. `.env` is git-ignored; `.env.example` ships only a placeholder. The app **refuses to boot** with a placeholder/empty `SECRET_KEY`. Tests: `test_secret_key_is_read_from_environment`, `test_env_file_is_gitignored`, `test_app_refuses_to_boot_with_placeholder_secret`. |
| 8 | **Error messages leak stack traces** | Forced a 404 and an unhandled 500 with `debug=False`; also reviewed `app.py`'s run config. | **PARTIAL** ⚠️ | With debug **off**, custom `404`/`500` pages render and leak **no** traceback or exception text (verified). **But** `app.py` runs `app.run(debug=True)` — in that mode the Werkzeug interactive debugger exposes full tracebacks **and a code-execution console** to anyone who can reach the page. Tests: `test_404_returns_custom_page_without_traceback`, `test_500_handler_hides_stack_trace`. |
| 9 | **CSRF** (supporting control) | POSTed a state-changing action with a missing and a wrong token. | **PASS** | Per-session token, constant-time compared; enforced on every non-safe method via a global `before_request`. Missing/invalid ⇒ 400. Tests: `test_csrf_missing_token_is_rejected`, `test_csrf_wrong_token_is_rejected`. |
| 10 | **Open redirect** (login `?next=`) | Fed external/`//`/absolute and backslash `next` values. | **PARTIAL** | `//evil.com`, `http(s)://evil.com` are correctly forced back to a local page (verified). **Gap:** `next=/\evil.com` slips past the `startswith('/')` / `not startswith('//')` check; some browsers normalise `\`→`/` and follow it off-site. Tests: `test_open_redirect_external_targets_blocked` (pass); `test_open_redirect_backslash_variant_blocked` (xfail — documents the gap). |
| 11 | **Content-Security-Policy / external scripts** | Inspected live response headers and templates. | **PARTIAL** | No `Content-Security-Policy` header is sent, and Bootstrap + Chart.js are loaded from `cdn.jsdelivr.net`. Autoescaping already blocks reflected XSS, but a CSP would harden against injected/3rd-party script and is expected for a security tool. |

---

## Findings & recommendations (ranked)

1. **HIGH — Debug mode exposes an RCE console.** `app.py` sets `DEBUG = True` and
   passes `debug=True` to `app.run`. The Werkzeug debugger then serves full
   tracebacks and an interactive Python console on any unhandled error.
   *Fix:* drive debug from an env var and default it **off**; never run with
   `debug=True` on any reachable interface. (Custom error pages are already in
   place and work once debug is off — see check #8.)

2. **MEDIUM — Session cookie not marked `Secure`.** `SESSION_COOKIE_SECURE=False`.
   *Fix:* set it `True` when served over HTTPS (env-driven), so the session
   cookie is never transmitted over plain HTTP.

3. **MEDIUM — Open-redirect via backslash in `next`.** `/\evil.com` bypasses the
   local-path check. *Fix:* reject any `next` containing `\`, or validate with
   `urlparse` and require an empty netloc, or only allow known endpoint names.

4. **LOW — No Content-Security-Policy; scripts from a public CDN.** *Fix:* add a
   restrictive CSP header and/or self-host Bootstrap/Chart.js (also removes the
   runtime dependency on jsdelivr).

## What was verified as solid
Parameterised SQL (no injection), output autoescaping (no stored/reflected XSS
on labels), route-level RBAC (no direct-URL bypass), salted one-way password
hashing, secrets kept in a git-ignored `.env` with a boot-time guard, CSRF on
all state changes, and per-IP login lockout with username-enumeration and
timing-oracle defences.

## Reproduce
```
python -m pytest tests/test_security.py -v
```
Runs against a throwaway `pwnm_test` schema; your real `pwnm` database is never
touched.
