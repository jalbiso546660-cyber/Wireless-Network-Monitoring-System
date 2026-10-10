"""
config.py
=========
Central configuration for PWNM, loaded from a .env file via python-dotenv and
exposed as MODULE CONSTANTS (import config; config.DB_HOST ...).

SECURITY RULE (from the brief): nothing secret is hard-coded in source. The DB
password and Flask secret come from environment variables loaded from a .env
file that is git-ignored; source ships only a .env.example template.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

# Load the .env next to this file, regardless of the current working directory,
# so every entry point (core modules, init_db, the Flask app) reads the same
# configuration.
_HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_HERE, ".env"))

# --- Database ---------------------------------------------------------------
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")          # XAMPP default = empty
DB_NAME = os.getenv("DB_NAME", "pwnm")
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))

# --- Flask (used from Phase 4 onward) ---------------------------------------
# Signs the session cookie. Must be random & secret in a real deployment.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-change-me")

# --- Scanning ---------------------------------------------------------------
# Default cadence for the scheduled scan loop (Phase 5). The live-tunable copy
# lives in the settings DB table; this is the fallback/default.
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "60"))


class Config:
    """Backwards-compatible accessor used by the data layer (data/db.py,
    init_db.py). It simply mirrors the module constants above so there is a
    single source of truth."""
    DB_HOST = DB_HOST
    DB_PORT = DB_PORT
    DB_USER = DB_USER
    DB_PASSWORD = DB_PASSWORD
    DB_NAME = DB_NAME
    DB_POOL_SIZE = DB_POOL_SIZE
    SECRET_KEY = SECRET_KEY
    SCAN_INTERVAL_SECONDS = SCAN_INTERVAL_SECONDS

    @classmethod
    def db_params(cls, include_database: bool = True) -> dict:
        """kwargs for mysql.connector. include_database=False is used by
        init_db.py, which connects BEFORE the `pwnm` database exists.

        auth_plugin is deliberately NOT pinned so this stays portable: MariaDB
        negotiates mysql_native_password and MySQL 8 negotiates
        caching_sha2_password automatically.
        """
        params = {
            "host": cls.DB_HOST,
            "port": cls.DB_PORT,
            "user": cls.DB_USER,
            "password": cls.DB_PASSWORD,
            "charset": "utf8mb4",
            "collation": "utf8mb4_unicode_ci",
            "connection_timeout": 5,
        }
        if include_database:
            params["database"] = cls.DB_NAME
        return params
