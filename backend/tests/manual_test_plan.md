# PWNM — Manual Test Plan

Execute each test in order, record what you observe in **Actual result**, mark
**Pass/Fail**, and screenshot the relevant screen. IDs are stable so you can
reference them from your documentation and defence.

## Legend
- **Status of feature**: ✅ implemented · 🟡 placeholder page (feature planned) ·
  ⛔ not implemented yet.
- Detection engine (alerts logic) is **Phase 6** and reports (PDF/CSV) are
  **Phase 7** — both are called out below and are *not* expected to work yet.

## Preconditions (do once, screenshot for evidence)
- **P0** XAMPP MySQL running; `python init_db.py` applied; at least one admin
  created (seed `admin` / `admin123`, or `python create_admin.py`).
- **P1** `.env` has a real `SECRET_KEY` (app refuses to boot otherwise).
- **P2** For a full ARP sweep: Npcap installed **and** the app started from an
  **Administrator** PowerShell. Without it the app auto-falls back to `arp -a`
  (fewer devices) — that fallback is itself test **T22**.
- **P3** Start the app: `python app.py` → browse to `http://127.0.0.1:5000`.

Create three accounts for the RBAC tests (or reuse existing):
`admin` (role admin), `monitor` (role monitor), `viewer` (role viewer).

---

## Authentication & session

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T01 | Login ✅ | Valid login works | 1) Open `/login` 2) Enter admin creds 3) Submit | Redirected to dashboard; navbar shows username | | |
| T02 | Login ✅ | Bad password rejected | Login admin with wrong password | Stays on `/login`; message "Invalid username or password."; HTTP 401 | | |
| T03 | Login ✅ | Username enumeration defence | Login with a **nonexistent** username | Identical error + timing to T02 (no "user not found") | | |
| T04 | Lockout ✅ | Brute-force lockout | Submit 6 bad logins quickly from one browser | After 5 failures, message "Too many failed attempts… seconds"; HTTP 429 | | |
| T05 | Logout ✅ | Session ends on logout | While logged in, click Logout | Redirected to `/login`; visiting `/dashboard` bounces to login | | |
| T06 | Auth guard ✅ | Protected pages need login | Log out, then open `/dashboard` directly | Redirected to `/login?next=/dashboard` | | |
| T07 | Session cookie ✅ | Cookie hardening | Inspect the `session` cookie in dev tools | Flags: `HttpOnly`, `SameSite=Lax` present | | |

## Role-based access control (RBAC)

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T08 | RBAC ✅ | Admin reaches admin pages | As **admin**, open `/admin/users` and `/admin/settings` | Both load (HTTP 200) | | |
| T09 | RBAC ✅ | Viewer blocked from admin | As **viewer**, open `/admin/users` by typing the URL | HTTP 403 Forbidden page | | |
| T10 | RBAC ✅ | Monitor blocked from admin | As **monitor**, open `/admin/settings` by URL | HTTP 403 | | |
| T11 | RBAC ✅ | Viewer cannot trigger scan | As **viewer**, POST `/scan/now` (or press Scan button if visible) | HTTP 403 | | |
| T12 | RBAC ✅ | Monitor can trigger scan | As **monitor**, press "Scan now" | Scan queued flash message; redirect to dashboard | | |
| T13 | RBAC ✅ | Viewer cannot authorize/block | As **viewer**, POST `/devices/<id>/authorize` by URL | HTTP 403 | | |

## Scanning & discovery

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T14 | Interface select ✅ | List adapters | Run `python -m core.interfaces` | Numbered adapter list; virtual/VPN flagged; best-guess adapter + subnet shown | | |
| T15 | Subnet derive ✅ | CIDR from IP/mask | In the list, confirm a `192.168.x.y / 255.255.255.0` row shows `…/24` | Correct CIDR (e.g. `192.168.1.0/24`) | | |
| T16 | Manual scan ✅ | One-shot scan+persist | With the app running, click **Scan now** (admin/monitor); or run a standalone discovery with `python -m core.scanner --prime` | Devices appear/refresh; access history shows joined/present; standalone run prints the discovered device table | | |
| T17 | Scheduled scan ✅ | Loop runs on interval | Start `python app.py`; wait one interval | New scan_session rows appear; dashboard "last scan Ns ago" updates | | |
| T18 | Vendor OUI ✅ | Manufacturer resolves | In device list, inspect a device with a real vendor MAC | Vendor column shows manufacturer (e.g. Apple/Google) | | |
| T19 | Randomised MAC ✅ | Private MAC labelled | Find a phone using a randomised MAC | Vendor shows "Randomized (private MAC)" | | |
| T20 | New device ✅ | New MAC detected | Connect a new device to the LAN, scan | Device appears; access history shows **joined** | | |
| T21 | Presence: left ✅ | Departure detected | Disconnect a device; let it miss ≥ `offline_after_missed` scans | Device flips offline; history shows **left** once | | |
| T22 | Fallback ✅ | No-Npcap path | Start app WITHOUT admin/Npcap | App logs "Scapy sweep unavailable… using arp -a fallback"; still lists devices | | |

## Device management

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T23 | Inventory ✅ | Device table + filters | Open `/devices`; apply status + presence filters | Table filters correctly; scroll/filter survive live refresh | | |
| T24 | Detail ✅ | Device detail + history | Click a device | Detail page shows MAC/IP/vendor/hostname + access-history timeline | | |
| T25 | Identity ✅ | MAC is identity | Note a device; reconnect it so DHCP gives a new IP; scan | Same single row; `last_ip` updated; **no** duplicate row | | |
| T26 | Authorize ✅ | Mark authorized | As admin, on a device click **Authorize** | Status badge → authorized; persists across scans | | |
| T27 | Block ✅ | Mark blocked + guidance | As admin, click **Block** | Status → blocked; page shows MAC-filter instruction for the router | | |
| T28 | Label ✅ | Friendly label | As admin, set a label and save | Label shown in list/detail/dashboard in place of MAC | | |

## Dashboard & live view

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T29 | Stat tiles ✅ | Counts render | Open dashboard | Online / unauthorized / blocked / open-alerts tiles show numbers | | |
| T30 | Live poll ✅ | Auto-refresh | Keep dashboard open ~10s while a scan runs | Device rows update in place without full reload | | |
| T31 | Charts ✅ | Trend + vendor charts | View the two charts | "Devices over time" line + "by vendor" doughnut render | | |
| T32 | Tab pause ✅ | Poll pauses hidden | Switch to another tab, return | Polling paused while hidden; resumes on focus | | |

## Admin — user management

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T33 | Create user ✅ | Add an account | As admin, `/admin/users` → fill Create user (name/role/password×2) → Create | New user appears in the table; can log in with that password | | |
| T33a | Weak password ✅ | Reject short pw | Create a user with a 4-char password | Rejected ("at least 8 characters"); user not created | | |
| T33b | Duplicate user ✅ | Reject dup name | Create a user with an existing username | Rejected ("already exists"); no duplicate row | | |
| T33c | Change role ✅ | Reset a role | Change a user's role dropdown → Set | Role badge updates; persists on reload | | |
| T33d | Disable/enable ✅ | Toggle access | Disable a user, then try logging in as them | Login fails while disabled; re-enable restores it | | |
| T33e | Reset password ✅ | Rotate a pw | Reset a user's password; log in with the new one | Old password fails; new password works | | |
| T33f | Self-lockout guard ✅ | Can't lock yourself out | As admin, try to Disable or demote **your own** account | Refused with a message; your account stays admin/active | | |
| T33g | Last-admin guard ✅ | Keep one admin | With only one active admin, try to demote/disable them | Refused ("last active admin") | | |

## Detection settings

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T34 | Edit settings ✅ | Tune thresholds in UI | As admin, `/admin/settings` → change a value → Save settings | "Saved N setting(s)"; values persist and re-display | | |
| T34a | Validation ✅ | Reject bad input | Set scan interval to `abc` or `1`, or a bad CIDR/time | Rejected with a specific message; value unchanged | | |
| T34b | Live tuning ✅ | Interval applies live | Change `scan_interval_seconds` and Save while app runs | Scheduler reschedules to the new interval without restart (also editable directly in DB) | | |

## Detection & alerts

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T35 | Alerts view ✅ | Alerts page loads | Open `/alerts` | Table of alerts with severity/rule/status; severity roll-up badges; status filters (All/New/Ack/Resolved) | | |
| T36 | UNAUTH_NEW ✅ | New device alert | Connect a new device; wait for a scan | An `UNAUTH_NEW` (**high**) alert appears; open-alerts tile increments | | |
| T36a | UNAUTH_RETURN ✅ | Unauthorized device | Let an `unauthorized` device be (re)discovered | `UNAUTH_RETURN` (medium) alert; a repeat within the 1-hour rate-limit window does **not** duplicate it | | |
| T36b | BLOCKED_SEEN ✅ | Blocked device present | Block a device (T27), then let it reappear | `BLOCKED_SEEN` (critical) alert while it is present | | |
| T36c | OFF_HOURS_JOIN ✅ | Off-hours join | Set quiet hours to cover now (Settings), let a device join | `OFF_HOURS_JOIN` (medium) alert | | |
| T36d | ARP_SPOOF (gateway) ✅ | Gateway MAC change | (Advanced) change the gateway's observed MAC vs the learned baseline | `ARP_SPOOF` (critical) alert; first-ever sight only learns the baseline (no alert) | | |
| T36d2 | ARP_SPOOF (conflict) ✅ | Two MACs, one IP | (Advanced, needs Npcap) two hosts claim one IP in the ARP window | `ARP_SPOOF` (critical) alert naming the IP + conflicting MACs | | |
| T36e | PORT_SCAN ✅ | Port-scan detection | (Needs Npcap+admin) run e.g. `nmap` against this host | `PORT_SCAN` (high) alert once a source crosses `portscan_port_threshold`. Without Npcap the sniffer is dormant (no false alerts) | | |
| T36e2 | IP_CHURN ✅ | Rapid IP changes | Let one MAC use ≥ `ipchurn_distinct_ips` IPs within `ipchurn_window_minutes` | `IP_CHURN` (medium) alert | | |
| T36e3 | SERVICE_ANOMALY ✅ | Sensitive ports open | A profiled device exposes a port on `service_watch_ports` (e.g. 3389) | `SERVICE_ANOMALY` (low) alert listing the watched port | | |
| T36f | Acknowledge ✅ | Ack an alert | As monitor/admin, click **Ack** on a new alert | Status → acknowledged | | |
| T36g | Resolve ✅ | Resolve an alert | Click **Resolve** | Status → resolved; drops out of the "New" filter | | |
| T36h | Alert RBAC ✅ | Viewer read-only | As **viewer**, confirm no Ack/Resolve buttons; POST ack by URL | Buttons hidden; direct POST returns 403 | | |

## Reports

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T37 | Reports page ✅ | Export options | Open `/reports` | Three cards: Device Inventory, Access History, Alert Summary — each with CSV + PDF | | |
| T37a | CSV export ✅ | Download CSV | Click "Download CSV" on Device Inventory | A `pwnm_devices_*.csv` downloads; opens in Excel with headers + rows | | |
| T37b | PDF export ✅ | Download PDF | Click "Download PDF" on Alert Summary | A `pwnm_alerts_*.pdf` downloads; renders a titled table | | |

## Security (see also security_self_assessment.md)

| ID | Feature | Objective | Steps | Expected result | Actual result | Pass/Fail |
|----|---------|-----------|-------|-----------------|---------------|-----------|
| T38 | CSRF ✅ | State change needs token | POST `/devices/<id>/label` without a token (curl/devtools) | HTTP 400 "CSRF token missing or invalid" | | |
| T39 | XSS ✅ | Label is escaped | As admin, set a label to `<script>alert(1)</script>`; reload detail page | Text shown literally; **no** alert box; source shows `&lt;script&gt;` | | |
| T40 | SQLi ✅ | Injection is inert | Login username `admin' OR '1'='1` | Login fails (401); app keeps working; users table intact | | |
| T41 | Headers ✅ | Security headers set | Inspect any response headers | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` | | |
| T42 | Error page ✅ | No stack trace (prod) | With `debug=False`, hit a broken URL / force an error | Friendly 404/500 page; **no** traceback. ⚠️ With `debug=True` (current `app.py`) the Werkzeug debugger DOES show tracebacks — see assessment | | |

---

### Coverage note for the panel
Every ✅ feature above is also covered by the automated pytest suite (`tests/`):
`134 passed, 1 xfailed`. The one xfail is a documented open-redirect edge case,
not a regression. `PORT_SCAN` (T36e) requires Npcap + admin for live packet
capture; its detection logic is fully unit-tested and the sniffer stays dormant
(no false alerts) where Npcap is unavailable. See `tests/README.md` for how to
run and interpret the suite.
