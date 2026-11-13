"""The gateway: every guard, in order, for one query request.

Order: authenticated principal -> quota -> query exists -> scope ->
parameters -> execute with a row cap -> audit line written -> result.
Every refusal is audited too.

If the audit line cannot be written, the caller gets an error and no data:
a query that is not on the record does not return rows.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

from .audit import AuditSink, redact, utc_now
from .params import ParamError, validate_params
from .queries import NamedQuery, derived_bindings
from .quota import QuotaExceeded, SlidingWindowQuota


@dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str
    scopes: frozenset[str]


class Denied(Exception):
    """Request refused. ``code`` is stable and safe to show to the caller."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class AuditUnavailable(Exception):
    pass


class Gateway:
    def __init__(
        self,
        conn: sqlite3.Connection,
        allowlist: dict[str, NamedQuery],
        quota: SlidingWindowQuota,
        audit: AuditSink,
        hard_row_cap: int = 200,
    ):
        self.conn = conn
        self.allowlist = allowlist
        self.quota = quota
        self.audit = audit
        self.hard_row_cap = hard_row_cap
        self._db_lock = threading.Lock()

    def visible_queries(self, principal: Principal | None) -> list[dict[str, Any]]:
        if principal is None:
            self._audit(None, "list_queries", None, None, "denied:unauthenticated", 0, False, 0.0)
            raise Denied("unauthenticated")
        try:
            self.quota.consume(principal.subject)
        except QuotaExceeded as exc:
            self._audit(principal, "list_queries", None, None, "denied:quota_exceeded", 0, False, 0.0)
            raise Denied("quota_exceeded", str(exc))
        out = [
            {
                "name": q.name,
                "description": q.description,
                "params": sorted(q.params),
                "max_rows": min(q.max_rows, self.hard_row_cap),
            }
            for q in self.allowlist.values()
            if q.scope in principal.scopes
        ]
        self._audit(principal, "list_queries", None, None, "ok", len(out), False, 0.0)
        return out

    def run(self, principal: Principal | None, name: Any, params: Any) -> dict[str, Any]:
        started = time.perf_counter()
        query = self.allowlist.get(name) if isinstance(name, str) else None

        def deny(code: str, detail: str = "", logged_params: Any = None) -> Denied:
            self._audit(principal, "run_query", name, logged_params, f"denied:{code}", 0, False, started)
            return Denied(code, detail)

        if principal is None:
            raise deny("unauthenticated")
        # Quota is charged before any other check, so probing for query names
        # or scopes is rate-limited too.
        try:
            self.quota.consume(principal.subject)
        except QuotaExceeded as exc:
            raise deny("quota_exceeded", str(exc))
        if query is None:
            raise deny("unknown_query")
        if query.scope not in principal.scopes:
            raise deny("forbidden", f"requires scope {query.scope}")
        try:
            values = validate_params(query.params, params)
        except ParamError as exc:
            raise deny("invalid_params", str(exc))

        logged = {
            k: (redact(v) if query.params[k].sensitive else v) for k, v in values.items()
        }
        limit = min(query.max_rows, self.hard_row_cap)
        try:
            with self._db_lock:
                cursor = self.conn.execute(query.sql, derived_bindings(query, values))
                fetched = cursor.fetchmany(limit + 1)
        except sqlite3.DatabaseError:
            self._audit(principal, "run_query", name, logged, "error:database", 0, False, started)
            raise Denied("database_error")
        truncated = len(fetched) > limit
        rows = [dict(r) for r in fetched[:limit]]

        self._audit(principal, "run_query", name, logged, "ok", len(rows), truncated, started)
        return {"query": query.name, "rows": rows, "row_count": len(rows), "truncated": truncated}

    def _audit(
        self,
        principal: Principal | None,
        tool: str,
        query: Any,
        params: Any,
        outcome: str,
        rows: int,
        truncated: bool,
        started: float,
    ) -> None:
        event = {
            "ts": utc_now(),
            "subject": principal.subject if principal else None,
            "client_id": principal.client_id if principal else None,
            "tool": tool,
            "query": query if isinstance(query, str) else None,
            "params": params,
            "outcome": outcome,
            "rows": rows,
            "truncated": truncated,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2) if started else 0.0,
        }
        try:
            self.audit.write(event)
        except Exception as exc:  # any sink failure means no result leaves the gateway
            raise AuditUnavailable("audit log unavailable; request refused") from exc
