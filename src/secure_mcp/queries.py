"""The allowlist: the only SQL this server can ever run.

Clients pick a query by name and pass parameters. There is no tool that
accepts SQL text. Adding a capability means adding an entry here, which goes
through code review like any other change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .params import DateParam, EnumParam, IntParam, ParamSpec, TextParam

SCOPE_READ = "erp:read"
SCOPE_FINANCE = "erp:finance"


@dataclass(frozen=True)
class NamedQuery:
    name: str
    description: str
    sql: str
    params: dict[str, ParamSpec]
    scope: str
    max_rows: int


class AllowlistError(ValueError):
    """An allowlist entry is not a single read-only statement."""


_LEADING = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
# SQLite accepts a WITH clause in front of DELETE, INSERT and UPDATE, so the
# leading keyword alone does not make a statement read-only.
_WRITE_WORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|REPLACE|UPSERT|CREATE|DROP|ALTER|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE)\b",
    re.IGNORECASE,
)


def check_statement(sql: str) -> None:
    """Reject anything that is not one read-only SELECT or WITH statement.

    This is a load-time lint for the allowlist, not a guard: it works on the
    SQL text. What actually stops a write at runtime is the read-only
    connection and the SQLite authorizer in db.py, which do not depend on it.
    """
    body = sql.strip().rstrip(";").strip()
    if ";" in body:
        raise AllowlistError("only one statement per query")
    if not _LEADING.match(body):
        raise AllowlistError("query must start with SELECT or WITH")
    if _WRITE_WORDS.search(body):
        raise AllowlistError("query must be read-only")


QUERIES: tuple[NamedQuery, ...] = (
    NamedQuery(
        name="customer_by_id",
        description="One customer by id.",
        sql="SELECT id, name, country, credit_limit_cents FROM customers WHERE id = :customer_id",
        params={"customer_id": IntParam(1, 1_000_000_000)},
        scope=SCOPE_READ,
        max_rows=1,
    ),
    NamedQuery(
        name="customer_search",
        description="Customers whose name starts with a prefix (case-insensitive). Wildcards in the prefix are matched literally.",
        sql=(
            "SELECT id, name, country FROM customers "
            "WHERE name LIKE :name_prefix_escaped || '%' ESCAPE '\\' ORDER BY name"
        ),
        params={"name_prefix": TextParam(40, r"[A-Za-z0-9 %_&.'-]+", sensitive=True)},
        scope=SCOPE_READ,
        max_rows=25,
    ),
    NamedQuery(
        name="invoices_for_customer",
        description="Invoices of one customer with a given status, newest first.",
        sql=(
            "SELECT id, issued_on, due_on, status, total_cents FROM invoices "
            "WHERE customer_id = :customer_id AND status = :status ORDER BY issued_on DESC"
        ),
        params={
            "customer_id": IntParam(1, 1_000_000_000),
            "status": EnumParam(("open", "paid", "void")),
        },
        scope=SCOPE_READ,
        max_rows=50,
    ),
    NamedQuery(
        name="overdue_invoices",
        description="Open invoices past their due date as of a given day, oldest first.",
        sql=(
            "SELECT i.id, c.name AS customer, i.due_on, i.total_cents FROM invoices i "
            "JOIN customers c ON c.id = i.customer_id "
            "WHERE i.status = 'open' AND i.due_on < :as_of ORDER BY i.due_on"
        ),
        params={"as_of": DateParam()},
        scope=SCOPE_FINANCE,
        max_rows=100,
    ),
    NamedQuery(
        name="revenue_by_month",
        description="Paid invoice totals per month for one year.",
        sql=(
            "SELECT substr(issued_on, 1, 7) AS month, SUM(total_cents) AS revenue_cents "
            "FROM invoices WHERE status = 'paid' AND substr(issued_on, 1, 4) = :year_text "
            "GROUP BY month ORDER BY month"
        ),
        params={"year": IntParam(2000, 2100)},
        scope=SCOPE_FINANCE,
        max_rows=12,
    ),
)


def derived_bindings(query: NamedQuery, values: dict) -> dict:
    """Bindings computed from validated values (never from raw input)."""
    bindings = dict(values)
    if query.name == "customer_search":
        prefix = values["name_prefix"]
        bindings["name_prefix_escaped"] = (
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        del bindings["name_prefix"]
    if query.name == "revenue_by_month":
        bindings["year_text"] = f"{values['year']:04d}"
        del bindings["year"]
    return bindings


def load_allowlist(queries: tuple[NamedQuery, ...] = QUERIES) -> dict[str, NamedQuery]:
    registry: dict[str, NamedQuery] = {}
    for query in queries:
        check_statement(query.sql)
        if query.name in registry:
            raise AllowlistError(f"duplicate query name: {query.name}")
        if query.max_rows < 1:
            raise AllowlistError(f"{query.name}: max_rows must be positive")
        registry[query.name] = query
    return registry
