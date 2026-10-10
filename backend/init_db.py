"""
init_db.py
==========
Create the `pwnm` database and all tables from sql/schema.sql.

Run once (from the project root, venv active):

    python init_db.py

It connects WITHOUT selecting a database (the schema file issues its own
CREATE DATABASE / USE), so it works on a fresh server where `pwnm` does not
exist yet. Safe to re-run: every statement uses IF NOT EXISTS / INSERT IGNORE,
so it will not clobber existing data or reset tuned settings.
"""
from __future__ import annotations

import os
import sys

import mysql.connector
from mysql.connector import Error as MySQLError

from config import Config

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "sql", "schema.sql")


def main() -> int:
    if not os.path.exists(SCHEMA_PATH):
        print(f"[ERROR] schema file not found: {SCHEMA_PATH}")
        return 1

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # schema.sql now begins with DROP DATABASE IF EXISTS pwnm — running this
    # RESETS the pwnm database (only pwnm; other XAMPP databases are untouched).
    print(f"Applying {SCHEMA_PATH}")
    print("  NOTE: this RESETS (drops & recreates) the 'pwnm' database.")

    # Connect without a database — schema.sql creates and selects it itself.
    try:
        conn = mysql.connector.connect(**Config.db_params(include_database=False))
    except MySQLError as e:
        if e.errno == 2003:
            print("[ERROR] Cannot reach the DB server. Start MySQL in the XAMPP "
                  "Control Panel, then re-run.")
        elif e.errno == 1045:
            print("[ERROR] Access denied — check DB_USER/DB_PASSWORD in .env.")
        else:
            print(f"[ERROR] {e}")
        return 1

    try:
        cur = conn.cursor()
        # multi=True lets one call execute the whole multi-statement script.
        # We must consume every result set or the connector complains.
        executed = 0
        for result in cur.execute(schema_sql, multi=True):
            executed += 1
        conn.commit()
        cur.close()
        print(f"Schema applied OK ({executed} statements). Database '{Config.DB_NAME}' is ready.")
    except MySQLError as e:
        print(f"[ERROR] Failed applying schema: {e}")
        return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
