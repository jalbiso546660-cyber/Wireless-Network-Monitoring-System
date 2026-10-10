"""
create_admin.py
===============
Interactively create a PWNM user (defaults to the 'admin' role). Use this to
make your first real administrator — there is NO hardcoded default password in
source; you type it here and it is stored only as a werkzeug hash.

    python create_admin.py

The password is read with getpass (not echoed to the screen) and confirmed.
The script also creates monitor/viewer accounts (choose the role at the prompt).
"""
from __future__ import annotations

import getpass
import sys

from werkzeug.security import generate_password_hash

from data import db, repos

VALID_ROLES = ("admin", "monitor", "viewer")
MIN_PASSWORD_LEN = 8


def main() -> int:
    if not db.ping():
        print("[ABORT] Database not reachable. Start MySQL (XAMPP) and run "
              "`python init_db.py` first.")
        return 1

    print("Create a PWNM user  (Ctrl+C to cancel)\n")

    username = input("Username: ").strip()
    if not username:
        print("Username is required.")
        return 1
    if repos.get_user_by_username(username):
        print(f"A user named '{username}' already exists.")
        return 1

    full_name = input("Full name (optional): ").strip() or None

    role = (input(f"Role {VALID_ROLES} [admin]: ").strip() or "admin").lower()
    if role not in VALID_ROLES:
        print(f"Invalid role '{role}'. Choose from {VALID_ROLES}.")
        return 1

    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LEN:
        print(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        return 1
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.")
        return 1

    # Hash here (web/security concern); the data layer never sees plaintext.
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
    user_id = repos.create_user(username, pw_hash, full_name, role, is_active=True)

    print(f"\nCreated user '{username}'  (role={role}, id={user_id}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
