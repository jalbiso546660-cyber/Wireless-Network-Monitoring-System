"""
backup_db.py
============
Dump the PWNM database to a timestamped .sql file so it can be restored after a
disk problem or an unclean MariaDB shutdown (the failure mode that corrupted the
Aria logs). Run it manually, or schedule it (Task Scheduler / cron).

    python backup_db.py                 # -> backend/backups/pwnm_YYYYmmdd-HHMMSS.sql
    python backup_db.py --out D:\safe   # choose a different output directory

It shells out to mysqldump using the same credentials as the app (from .env via
config), so there are no secrets in this file. Restore with:
    mysql -u root pwnm < backups/pwnm_YYYYmmdd-HHMMSS.sql
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime

from config import Config

# XAMPP ships mysqldump here; fall back to whatever is on PATH.
_XAMPP_DUMP = r"C:\xampp\mysql\bin\mysqldump.exe"


def _find_mysqldump() -> str | None:
    if os.path.exists(_XAMPP_DUMP):
        return _XAMPP_DUMP
    return shutil.which("mysqldump")


def main() -> int:
    ap = argparse.ArgumentParser(description="Back up the PWNM database.")
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "backups"),
        help="output directory (default: backend/backups)")
    args = ap.parse_args()

    dump = _find_mysqldump()
    if not dump:
        print("[ERROR] mysqldump not found. Install it or start XAMPP "
              "(expected at C:\\xampp\\mysql\\bin\\mysqldump.exe).")
        return 1

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(args.out, f"pwnm_{stamp}.sql")

    cmd = [dump, "-h", Config.DB_HOST, "-P", str(Config.DB_PORT),
           "-u", Config.DB_USER]
    if Config.DB_PASSWORD:
        cmd.append(f"-p{Config.DB_PASSWORD}")     # mysqldump wants -p<pwd> joined
    cmd += ["--single-transaction", "--databases", Config.DB_NAME]

    print(f"Backing up '{Config.DB_NAME}' -> {out_path}")
    try:
        with open(out_path, "wb") as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
    except OSError as e:
        print(f"[ERROR] could not run mysqldump: {e}")
        return 1

    if proc.returncode != 0:
        print("[ERROR] mysqldump failed:\n" + proc.stderr.decode("utf-8", "replace"))
        # Don't leave a half-written/empty dump behind.
        if os.path.exists(out_path) and os.path.getsize(out_path) == 0:
            os.remove(out_path)
        return 1

    size = os.path.getsize(out_path)
    print(f"OK — wrote {size:,} bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
