"""
data/db.py
==========
Connection pooling + tiny query helpers for MySQL 8 / MariaDB 10.4.

WHY A POOL: the scan loop and (later) every web request may need a connection
at once. A fixed pool (size 5) hands out and recycles a bounded set instead of
paying TCP+auth on every call.

WHY THE HELPERS: query() and execute() are the ONLY way SQL runs, and both take
values as a separate params tuple — SQL is NEVER built by string formatting.
That is the structural defence against SQL injection. get_conn() guarantees the
connection is always committed-or-rolled-back and returned to the pool.

No Flask imports here.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error as MySQLError
from mysql.connector import errorcode
from mysql.connector.pooling import MySQLConnectionPool

from config import Config

log = logging.getLogger(__name__)

_pool: MySQLConnectionPool | None = None


class DatabaseError(RuntimeError):
    """Wraps low-level connector errors with a human-readable hint."""


def _friendly(err: MySQLError) -> str:
    if err.errno == 2003:
        return ("Cannot reach the database server. Is MariaDB/MySQL running? "
                "In XAMPP, open the Control Panel and press Start next to MySQL.")
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:      # 1045
        return ("Access denied — check DB_USER/DB_PASSWORD in .env "
                "(XAMPP default: user 'root', empty password).")
    if err.errno == errorcode.ER_BAD_DB_ERROR:             # 1049
        return (f"Database '{Config.DB_NAME}' does not exist. "
                "Create it with:  python init_db.py")
    return f"Database error [{err.errno}]: {err.msg}"


def get_pool() -> MySQLConnectionPool:
    """Create the pool on first use (lazy) so importing never needs the DB up."""
    global _pool
    if _pool is None:
        try:
            _pool = MySQLConnectionPool(
                pool_name="pwnm_pool",
                pool_size=Config.DB_POOL_SIZE,      # 5 by default
                pool_reset_session=True,
                **Config.db_params(include_database=True),
            )
            log.info("DB pool created (size=%d) -> %s:%d/%s",
                     Config.DB_POOL_SIZE, Config.DB_HOST, Config.DB_PORT,
                     Config.DB_NAME)
        except MySQLError as e:
            raise DatabaseError(_friendly(e)) from e
    return _pool


@contextmanager
def get_conn():
    """Borrow a pooled connection; commit on success, roll back on error, and
    ALWAYS return it to the pool. Use directly for multi-statement transactions,
    or via query()/execute() for one-offs."""
    try:
        conn = get_pool().get_connection()
        # Revive a connection left stale by a DB restart so the caller gets a
        # live session instead of a "MySQL server has gone away" error.
        conn.ping(reconnect=True, attempts=2, delay=1)
    except MySQLError as e:
        raise DatabaseError(_friendly(e)) from e
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()          # returns to pool (not a real socket close)


def query(sql: str, params: tuple | None = None) -> list[dict]:
    """Run a SELECT; return all rows as a list of dicts (parameterized)."""
    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params or ())
            return cur.fetchall()
        finally:
            cur.close()


def query_one(sql: str, params: tuple | None = None) -> dict | None:
    """Run a SELECT; return the first row or None (parameterized)."""
    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params or ())
            return cur.fetchone()
        finally:
            cur.close()


def execute(sql: str, params: tuple | None = None) -> int:
    """Run an INSERT/UPDATE/DELETE; return lastrowid (inserts) or rowcount."""
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute(sql, params or ())
            return cur.lastrowid or cur.rowcount
        finally:
            cur.close()


def executemany(sql: str, seq_params: list[tuple]) -> int:
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.executemany(sql, seq_params)
            return cur.rowcount
        finally:
            cur.close()


def ping() -> bool:
    """True if a simple round-trip to the DB succeeds."""
    try:
        return query_one("SELECT 1 AS ok") == {"ok": 1}
    except DatabaseError as e:
        log.error("%s", e)
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        ver = query_one("SELECT VERSION() AS v")["v"]
        print(f"Connected OK. Server version: {ver}")
        tables = [next(iter(r.values())) for r in query("SHOW TABLES")]
        print(f"Tables in '{Config.DB_NAME}': {', '.join(tables) or '(none — run init_db.py)'}")
    except DatabaseError as e:
        print(f"[DB PROBLEM] {e}")
        raise SystemExit(1)
