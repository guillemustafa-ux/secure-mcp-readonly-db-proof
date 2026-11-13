"""Read-only database access with two independent guards.

1. The file is opened with SQLite's ``mode=ro`` URI, so SQLite refuses to
   modify the database file. On its own that still allows ``VACUUM INTO``,
   ``ATTACH`` and temporary tables, which is why there is a second layer.
2. An authorizer callback allows only reads. It denies writes, ATTACH,
   PRAGMA, schema changes and transactions, and it limits which tables can be
   read, so a table outside the allowlist (payroll here) stays unreadable even
   if a query mentioning it slipped into the allowlist.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

ALLOWED_TABLES = frozenset({"customers", "invoices", "invoice_lines"})

# Functions the allowlisted queries need. Anything else is denied.
ALLOWED_FUNCTIONS = frozenset({"substr", "sum", "count", "lower", "upper", "like"})


def _authorizer(action: int, arg1, arg2, db_name, trigger):  # noqa: ANN001
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        # arg1 = table name, arg2 = column name
        return sqlite3.SQLITE_OK if arg1 in ALLOWED_TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        # arg2 = function name
        return sqlite3.SQLITE_OK if (arg2 or "").lower() in ALLOWED_FUNCTIONS else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


def connect_readonly(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(path)
    uri = f"{path.resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.set_authorizer(_authorizer)
    return conn
