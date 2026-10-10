"""
PWNM data-access layer (``data`` package).

Two modules:
  * db.py    — the MySQL/MariaDB connection pool and small query helpers.
  * repos.py — repository functions (the only place that knows SQL).

Everything here uses PARAMETERIZED queries exclusively — values are passed as
a params tuple, never formatted into the SQL string — which is the primary
defence against SQL injection. This layer has no knowledge of Flask.
"""
