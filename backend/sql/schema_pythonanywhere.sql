-- PythonAnywhere-compatible schema: run this INSIDE the MySQL console
-- they give you, already connected to your own database. Do NOT add a
-- USE/CREATE DATABASE line — their free tier doesn't allow it.

-- ===========================================================================
-- PWNM — database schema
-- Target: MySQL 8.x / MariaDB 10.4 (portable subset). Charset utf8mb4.
--
-- CORE DESIGN RULE (defend this to the panel):
--   The MAC address is the DEVICE IDENTITY (devices.mac_address is UNIQUE).
--   DHCP reassigns IPs constantly, so the IP is NOT a stable key — it is the
--   mutable column devices.last_ip. Everything upserts by MAC.
--
-- DROP-AND-RECREATE HEADER: this file RESETS the database for a clean dev
-- slate. It drops ONLY the `pwnm` database (your other XAMPP databases are
-- untouched). Apply with:  python init_db.py   (or: mysql -u root < sql/schema.sql)
-- ===========================================================================



-- ---------------------------------------------------------------------------
-- users — application accounts and their role (RBAC also enforced in Flask)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    -- werkzeug.security hash (pbkdf2:sha256). NEVER store plaintext passwords.
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(128),
    role          ENUM('admin','monitor','viewer') NOT NULL DEFAULT 'viewer',
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- devices — one row per physical device, keyed by MAC (the identity)
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    mac_address   VARCHAR(17)  NOT NULL UNIQUE,      -- aa:bb:cc:dd:ee:ff
    last_ip       VARCHAR(45),                       -- 45 = future IPv6 room
    hostname      VARCHAR(255),
    vendor        VARCHAR(255),                      -- OUI manufacturer / randomised label
    device_label  VARCHAR(128),                      -- friendly name set by admin
    os_guess      VARCHAR(128),                      -- OS estimate from nmap (Module 2.4)
    open_ports    VARCHAR(255),                      -- CSV of open TCP ports from nmap (Module 2.4)
    -- authorization STATE. 'blocked' does NOT cut traffic — it flags the device
    -- so every reappearance raises a critical alert + a MAC-filter instruction.
    status        ENUM('authorized','unauthorized','blocked')
                  NOT NULL DEFAULT 'unauthorized',
    is_online     TINYINT(1)   NOT NULL DEFAULT 0,
    first_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    authorized_by INT          NULL,
    authorized_at DATETIME     NULL,
    block_reason  VARCHAR(255) NULL,                  -- why an admin blocked it (Module 3.4)
    notes         TEXT,
    CONSTRAINT fk_devices_authorized_by
        FOREIGN KEY (authorized_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_devices_status (status),
    INDEX idx_devices_online (is_online),
    INDEX idx_devices_last_seen (last_seen)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- scan_sessions — one row per scan run (audit trail of when/what/who)
-- ---------------------------------------------------------------------------
CREATE TABLE scan_sessions (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    started_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   DATETIME     NULL,
    subnet        VARCHAR(45),
    interface     VARCHAR(128),
    devices_found INT          NOT NULL DEFAULT 0,
    triggered_by  ENUM('scheduler','manual') NOT NULL DEFAULT 'scheduler',
    user_id       INT          NULL,
    CONSTRAINT fk_scan_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scan_started (started_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- access_logs — device presence history (joined / present / left)
-- ---------------------------------------------------------------------------
CREATE TABLE access_logs (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_id  INT    NOT NULL,
    scan_id    INT    NULL,
    ip_address VARCHAR(45),
    event      ENUM('joined','present','left') NOT NULL,
    seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_device
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    CONSTRAINT fk_log_scan
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE SET NULL,
    INDEX idx_log_device (device_id),
    INDEX idx_log_seen (seen_at),
    INDEX idx_log_event (event)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- alerts — output of the detection engine (Phase 6)
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_id  INT    NULL,
    rule_code  VARCHAR(32)  NOT NULL,
    severity   ENUM('low','medium','high','critical') NOT NULL,
    title      VARCHAR(255) NOT NULL,
    detail     TEXT,
    status     ENUM('new','acknowledged','resolved') NOT NULL DEFAULT 'new',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ack_by     INT      NULL,
    ack_at     DATETIME NULL,
    resolution_note VARCHAR(255) NULL,     -- reason recorded when an alert is resolved
    CONSTRAINT fk_alert_device
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT fk_alert_ackby
        FOREIGN KEY (ack_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_alert_status (status),
    INDEX idx_alert_severity (severity),
    INDEX idx_alert_rule (rule_code),
    INDEX idx_alert_created (created_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- settings — runtime-tunable key/value config. Detection thresholds live HERE,
-- never hard-coded, so they can be adjusted live during the defense.
-- ---------------------------------------------------------------------------
CREATE TABLE settings (
    setting_key   VARCHAR(64)  PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    description   VARCHAR(255)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- setting_audit — accountability trail for configuration changes: who changed
-- which setting, when, and from what value to what value.
-- ---------------------------------------------------------------------------
CREATE TABLE setting_audit (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(64)  NOT NULL,
    old_value   VARCHAR(255),
    new_value   VARCHAR(255),
    changed_by  INT,
    changed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_changed (changed_at)
) ENGINE=InnoDB;

-- ===========================================================================
-- SEED DATA
-- ===========================================================================

-- Detection / scan settings (tunable at runtime).
INSERT INTO settings (setting_key, setting_value, description) VALUES
 ('scan_interval_seconds',    '60',    'Seconds between scheduled scans'),
 ('profile_interval_seconds', '300',   'Seconds between nmap device-profiling passes (open ports + OS)'),
 ('offline_after_missed',     '3',     'Consecutive scans a device may be missed before it is marked offline/left'),
 ('portscan_port_threshold',  '15',    'Distinct destination ports from one source within the window to flag a port scan'),
 ('portscan_window_seconds',  '60',    'Sliding window (seconds) for port-scan detection'),
 ('quiet_hours_start',        '00:00', 'Start of quiet hours (off-hours join detection)'),
 ('quiet_hours_end',          '05:00', 'End of quiet hours'),
 ('unauth_return_rate_limit_seconds', '3600', 'Minimum seconds between repeat UNAUTH_RETURN alerts for the same device (spec: one per device per hour)'),
 ('alert_dedup_seconds',      '300',   'Default lookback window that suppresses duplicate alerts'),
 ('ipchurn_distinct_ips',     '3',     'Distinct IPs one MAC may use in the window before IP_CHURN fires'),
 ('ipchurn_window_minutes',   '10',    'Sliding window (minutes) for IP-churn detection'),
 ('arp_conflict_window_seconds', '120', 'Sliding window (seconds) for two-MACs-one-IP ARP-conflict detection'),
 ('service_watch_ports',      '22,23,21,445,3389,5900,3306,1433', 'Sensitive TCP ports that raise SERVICE_ANOMALY when found open'),
 ('log_retention_days',       '90',    'Access logs and finished scans older than this many days are pruned nightly');

-- Seed administrator account.
-- Username: admin   Password: admin123   (CHANGE THIS ON FIRST LOGIN)
-- The password_hash below is a real werkzeug pbkdf2:sha256 hash of 'admin123'.
INSERT INTO users (username, password_hash, full_name, role, is_active) VALUES
 ('admin',
  'pbkdf2:sha256:1000000$bcOjYNHdHaaGOlO8$fd137c695c96bbfe21e91a9e2c12d2fff2e31f1bd9bf0f36b2d5edac71118aac',
  'Administrator', 'admin', 1);
