# PWNM test suite

## What's here
| File | Kind | Needs MySQL? | Needs network? |
|------|------|:---:|:---:|
| `test_unit_interfaces.py` | `derive_subnet()` edge cases | no | no |
| `test_unit_vendor.py` | `vendor.lookup_vendor()` + randomised-MAC detection (engine faked) | no | no |
| `test_nmap_scan.py` | `nmap_profile()` open-ports + OS parsing (python-nmap mocked) | no | no |
| `test_unit_upsert_identity.py` | `upsert_device()` MAC-identity rules | **yes** | no |
| `test_unit_transitions.py` | joined/present/left + `reconcile_offline` boundary | **yes** | no |
| `test_detection_rules.py` | all 6 detection rules + port-scan tracker (pure, synthetic input, boundaries) | no | no |
| `test_integration_scan_cycle.py` | full scan→persist→reconcile via `scheduler.run_scan_cycle` + nmap profiling job (mocked) | **yes** | no |
| `test_integration_alerts.py` | detection engine end-to-end: alert generation, dedup, UNAUTH_RETURN rate limit, ARP-spoof baseline | **yes** | no |
| `test_alerts_routes.py` | alerts page + acknowledge/resolve + RBAC | **yes** | no |
| `test_reports.py` | CSV/PDF generation + download routes | **yes** | no |
| `test_admin_pages.py` | user CRUD + settings editor + guards | **yes** | no |
| `test_access_control.py` | table-driven RBAC matrix (every route × role) | **yes** | no |
| `test_security.py` | SQLi, XSS, CSRF, session, secrets, error pages | **yes** | no |

The isolated `pwnm_test` schema is created, seeded, and **dropped** by
`conftest.py`. A hard assert refuses to run unless the DB name ends in `_test`,
so your real `pwnm` database is never touched.

## Run
```powershell
.\.venv\Scripts\Activate.ps1
pip install pytest            # once
python -m pytest              # all
python -m pytest -v           # verbose (shows every skipped/xfail line)
python -m pytest tests/test_security.py -v
```
Requires XAMPP MySQL running (same `.env` DB credentials). If MySQL is down, the
DB-backed tests **skip** with a clear message; the pure-unit tests still run.

## Expected baseline result (a clean, correct build)
`216 passed, 1 xfailed` (0 skipped) — the system aligned to the documented
nine-module architecture (Modules 1–9).
- **1 xfailed** = the known open-redirect backslash gap (documented, not a
  regression).
Anything **failed** or **errored** is a real signal — read the map below.

## Which tests should FAIL if you have a real bug — and how to read each

| If this FAILS… | …the bug it caught |
|----------------|--------------------|
| `test_unit_interfaces` | `derive_subnet` isn't collapsing host bits / mishandles a mask (e.g. returns `192.168.1.23/24`). The ARP sweep would scan the wrong range. |
| `test_locally_administered_*` | Randomised-MAC detection reads the wrong bit. Phones on private MACs would be mislabelled and treated as brand-new every rotation. |
| `test_lookup_randomised_is_labelled` | A private MAC is being sent to the OUI engine instead of short-circuited → wrong "vendor". |
| `test_same_mac_different_ip_keeps_one_row` | **Identity bug:** DHCP IP change spawns a duplicate device row. The whole "MAC is identity" design is broken. |
| `test_different_mac_same_ip_creates_two_rows` | Upsert is keying on IP, not MAC — two devices would collapse into one. |
| `test_rescan_does_not_overwrite_admin_status` | A routine scan is clobbering an admin's authorize/block decision. |
| `test_rescan_with_missing_attrs_keeps_known_values` | `COALESCE` lost — a scan that can't resolve vendor/hostname nulls out known data. |
| `test_new_devices_join_then_present` | joined/present split is wrong (prior-online snapshot taken at the wrong time). Access history would be misleading. |
| `test_left_fires_exactly_at_threshold_not_before` | Off-by-one in `reconcile_offline`: devices marked "left" too early or too late vs `offline_after_missed`. |
| `test_left_logged_exactly_once_across_a_scan_sequence` | Duplicate/again-firing `left` events — the audit trail double-counts departures. |
| `test_scan_cycle_falls_back_when_npcap_unavailable` | The no-Npcap safety net is broken — on a non-admin box scans would silently produce nothing. |
| `test_scan_cycle_reconciles_departed_device` | The scheduled path doesn't reconcile — departures never register in production. |
| `test_scan_cycle_never_raises_on_scanner_error` | One bad scan cycle would kill the whole scheduler loop. |
| `test_access_control_matrix` (any cell) | An RBAC hole: a role reaches a route it shouldn't (or an allowed role is wrongly blocked). The printed line names the exact route/role/expected/got. |
| `test_wrong_role_is_403_even_for_missing_device` | RBAC is evaluated after the 404 check, leaking existence / letting the wrong role through. |
| `test_sqli_*` | SQL is being built by string formatting somewhere — injection is live. |
| `test_xss_*` | Autoescaping got turned off (or a value is marked `|safe`) — stored XSS via labels. |
| `test_csrf_*` | CSRF enforcement regressed — state-changing POSTs accept forged requests. |
| `test_session_cookie_changes_after_login` | Session isn't rotated on auth — session-fixation exposure. |
| `test_passwords_stored_as_pbkdf2_hash` / `…no_plaintext_password_column` | Passwords stored weakly or in plaintext. |
| `test_app_refuses_to_boot_with_placeholder_secret` | The boot-time secret guard was removed — app could run with a known signing key. |
| `test_404_returns_custom_page…` / `test_500_handler_hides_stack_trace` | Error handling leaks tracebacks even with debug off. |
| `test_within_quiet_hours_boundaries` | Quiet-hours window math is wrong (esp. the midnight wrap) — off-hours joins mis-flagged. |
| `test_port_scan_tracker_boundary` | Port-scan threshold/window off-by-one, or repeated hits on one port inflate the count. |
| `test_alert_deduplication_within_window` | Dedup broken — a persistent condition would spam identical alerts every scan. |
| `test_engine_arp_spoof_learns_then_alerts` | ARP-spoof baseline logic wrong (alerts on first sight, or never alerts on a real change). |
| `test_monitor_can_acknowledge` / `test_viewer_cannot_acknowledge` | Alert ack/resolve RBAC hole. |
| `test_build_pdf_is_a_pdf` / `test_download_route_*` | Report generation or the download endpoints are broken. |

### The one remaining xfail
Fix the backslash open-redirect → `test_open_redirect_backslash_variant_blocked`
flips from xfail to xpass; then drop the `xfail` marker.
