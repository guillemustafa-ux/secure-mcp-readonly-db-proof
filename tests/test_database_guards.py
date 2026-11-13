"""The two database guards, each tested on its own."""

import sqlite3

import pytest

from secure_mcp.db import _authorizer, connect_readonly

from conftest import count_rows


def test_authorizer_blocks_writes(db_path):
    conn = connect_readonly(db_path)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute("DELETE FROM customers")
    assert count_rows(db_path, "customers") > 0


def test_authorizer_blocks_writes_even_on_a_writable_connection(db_path, tmp_path):
    copy = tmp_path / "copy.sqlite"
    copy.write_bytes(db_path.read_bytes())
    conn = sqlite3.connect(copy)  # read-write: guard 1 removed
    conn.set_authorizer(_authorizer)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute("DELETE FROM customers")
    conn.set_authorizer(None)
    assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] > 0


def test_read_only_file_blocks_writes_even_without_the_authorizer(db_path):
    conn = connect_readonly(db_path)
    conn.set_authorizer(None)  # remove guard 2; guard 1 must still hold
    before = count_rows(db_path, "customers")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM customers")
    assert count_rows(db_path, "customers") == before


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM payroll",
        "SELECT name FROM customers UNION SELECT full_name FROM payroll",
        "PRAGMA table_info(payroll)",
        "SELECT * FROM sqlite_master",
    ],
)
def test_authorizer_blocks_reads_outside_the_allowed_tables(db_path, sql):
    conn = connect_readonly(db_path)
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute(sql).fetchall()


def test_authorizer_blocks_functions_outside_the_short_list(db_path):
    # hex() is harmless and works on a plain connection, so only the
    # authorizer's function list can refuse it.
    assert sqlite3.connect(":memory:").execute("SELECT hex('a')").fetchone() == ("61",)
    conn = connect_readonly(db_path)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized to use function: hex"):
        conn.execute("SELECT hex(name) FROM customers").fetchall()


def test_attach_is_blocked(db_path, tmp_path):
    conn = connect_readonly(db_path)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute("ATTACH DATABASE ? AS other", (str(tmp_path / "other.db"),))


def test_missing_database_is_not_created(tmp_path):
    with pytest.raises(FileNotFoundError):
        connect_readonly(tmp_path / "nope.sqlite")
    assert not (tmp_path / "nope.sqlite").exists()
