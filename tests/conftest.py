from __future__ import annotations

import pytest

from secure_mcp.db import connect_readonly
from secure_mcp.gateway import Gateway, Principal
from secure_mcp.queries import load_allowlist
from secure_mcp.quota import SlidingWindowQuota
from secure_mcp.schema import create_database

READER = Principal("ana", "test-client", frozenset({"erp:read"}))
FINANCE = Principal("fin", "test-client", frozenset({"erp:read", "erp:finance"}))


class MemorySink:
    def __init__(self):
        self.events: list[dict] = []

    def write(self, event: dict) -> None:
        self.events.append(event)


class BrokenSink:
    def write(self, event: dict) -> None:
        raise OSError("disk full")


@pytest.fixture(scope="session")
def db_path(tmp_path_factory):
    return create_database(tmp_path_factory.mktemp("db") / "erp.sqlite")


@pytest.fixture
def sink():
    return MemorySink()


@pytest.fixture
def make_gateway(db_path, sink):
    def _make(quota=None, audit=None, hard_row_cap=200):
        return Gateway(
            conn=connect_readonly(db_path),
            allowlist=load_allowlist(),
            quota=quota or SlidingWindowQuota(1000, 60),
            audit=audit or sink,
            hard_row_cap=hard_row_cap,
        )

    return _make


def count_rows(db_path, table: str) -> int:
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()
