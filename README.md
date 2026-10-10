# PWNM — Python Wireless Network Monitor

A network security monitoring system that discovers devices on a local wireless network, tracks their presence over time, and raises alerts when it detects suspicious behavior — unauthorized devices, ARP spoofing, port scanning, and more. Built with Flask and MySQL/MariaDB.

## What it does

PWNM continuously scans the local network (ARP sweep), keeps an inventory of every device it finds, and runs that activity through a rule-based detection engine. Administrators review and act on what it finds through a web dashboard.

- **Device discovery** — ARP sweep (Scapy) with an `arp -a` fallback when raw-socket access isn't available; nmap-based profiling (open ports, OS guess) on a slower background schedule
- **Presence tracking** — join/leave/present history per device, with an occupancy timeline
- **Threat detection** — 9 rules evaluated on every scan, with every threshold configurable at runtime (nothing hardcoded):

  | Rule | Severity | Trigger |
  |---|---|---|
  | New unknown device | High | A MAC never seen before joins |
  | Unauthorized device returned | Medium | A known, unapproved device reconnects |
  | Flagged device seen | Critical | A device marked flagged is on the network |
  | Gateway impersonation | Critical | The router's MAC changed from its learned baseline (ARP spoofing) |
  | Two devices, one IP | Critical | Two MACs claim the same IP (ARP poisoning) |
  | Port scanning | High | One source probes many ports in a short window |
  | Off-hours join | Medium | A device joins during configured quiet hours |
  | Rapid IP changes | Medium | One MAC cycles through several IPs quickly |
  | Risky service exposed | Low | A device has a sensitive port open (SSH, RDP, file sharing...) |

- **Role-based access control** — Admin / Monitor / Viewer, enforced at the route level (not just hidden UI)
- **Dashboard** — live device table, stat tiles, network throughput/ping, and Chart.js visualizations (occupancy, alerts by severity/rule/time, device status, vendor distribution, presence timeline) with date-range filtering
- **Reports** — CSV and PDF exports (device inventory, access history, alert summary) via ReportLab
- **Admin tools** — user management, detection-setting tuning with plain-English explanations, a configuration audit trail, and data-retention pruning

## Security

Built around six protections, one per pillar of the CIA + AAA security model:

| Pillar | How it's handled |
|---|---|
| Confidentiality | Passwords hashed with `pbkdf2:sha256`; all SQL parameterized; Content-Security-Policy with a strict `script-src` |
| Integrity | CSRF tokens (constant-time comparison) on every state-changing request; Jinja autoescaping on all output |
| Availability | Brute-force lockout (5 failed logins → 5-minute lock); detection is passive-only — it never disrupts the network it monitors |
| Authentication | Timing-safe login (one hash check whether or not the account exists); generic error messages |
| Authorization | Role checks enforced server-side on every route, returning 403 before any 404 — never relies on hiding a link |
| Accountability | A full audit trail: every setting change and every device authorization is logged with who did it and when |

PWNM never sends deauthentication frames or performs any form of active network attack — detection is entirely passive.

## Tech stack

**Backend:** Python 3.12, Flask, Flask-Login, MySQL/MariaDB (via `mysql-connector-python`), Scapy, APScheduler, python-nmap, ReportLab
**Frontend:** Jinja2 templates, Bootstrap 5, Chart.js, vanilla JavaScript (no build step)
**Testing:** pytest — 274 tests across unit, integration, security, and access-control suites, run against an isolated test database

## Project structure

```
pwnm/
├── backend/
│   ├── app.py              # Flask application factory
│   ├── config.py           # Environment-based configuration
│   ├── scheduler.py        # Background scan loop (APScheduler)
│   ├── core/                # Network layer: ARP sweep, sniffer, interfaces, nmap
│   ├── data/                 # Database pool + all repository/query functions
│   ├── detection/            # Pure detection rules + the evaluation engine
│   ├── reports/               # CSV/PDF report generation
│   ├── web/routes/            # Flask blueprints (auth, devices, alerts, charts, settings, reports)
│   ├── sql/schema.sql          # Database schema + seed data
│   └── tests/                   # pytest suite
└── frontend/
    ├── templates/            # Jinja2 HTML templates
    └── static/                # CSS, JavaScript
```

## Getting started

### Requirements
- Python 3.12+
- MySQL or MariaDB (e.g. via XAMPP)
- Administrator/root privileges and Npcap (Windows) for live packet capture — the app runs without them, with reduced detection capability

### Setup

```bash
git clone https://github.com/jalbiso546660-cyber/Wireless-Network-Monitoring-System.git
cd Wireless-Network-Monitoring-System
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

Configure the database:
```bash
cd backend
copy .env.example .env          # then edit .env with your DB credentials
python init_db.py               # creates the database and tables
```

Run it:
```bash
python app.py
```

Open **http://127.0.0.1:5000** and log in:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Administrator |

**Change this password immediately after first login**, especially on any shared or public deployment.

### Running the tests

```bash
cd backend
python -m pytest
```

## A note on deployment

PWNM's device discovery uses ARP, a Layer-2 broadcast protocol that routers do not forward. This means it only works when run on a host **inside** the network it's monitoring — it cannot be deployed to a conventional cloud/web host and still detect devices, since that host would be on a completely different network. The correct deployment model is a machine on the local network (a laptop, a Raspberry Pi) reachable over that LAN or a VPN.

## License

Academic project — built for coursework purposes.
