import pytest

from secure_mcp.queries import QUERIES, AllowlistError, NamedQuery, check_statement, load_allowlist


def test_every_allowlisted_query_is_a_single_read_statement():
    registry = load_allowlist()
    assert set(registry) == {q.name for q in QUERIES}


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM customers",
        "UPDATE customers SET name = 'x'",
        "SELECT 1; DROP TABLE customers",
        "SELECT 1; SELECT 2",
        "PRAGMA writable_schema = 1",
        "ATTACH DATABASE 'x.db' AS x",
        "  insert into customers values (1)",
        # SQLite accepts WITH in front of a write
        "WITH d AS (SELECT 1) DELETE FROM invoices",
        "WITH d AS (SELECT 1) INSERT INTO customers SELECT * FROM customers",
        "with d as (select 1) update invoices set status = 'paid'",
        "WITH d AS (SELECT 1) REPLACE INTO customers SELECT * FROM customers",
    ],
)
def test_lint_rejects_anything_but_one_read_only_select(sql):
    with pytest.raises(AllowlistError):
        check_statement(sql)


def test_lint_accepts_with_and_trailing_semicolon():
    check_statement("WITH a AS (SELECT 1 AS x) SELECT x FROM a;")


def test_duplicate_names_are_rejected():
    q = QUERIES[0]
    with pytest.raises(AllowlistError):
        load_allowlist((q, q))


@pytest.mark.parametrize("sql", ["DELETE FROM invoices", "WITH d AS (SELECT 1) DELETE FROM invoices"])
def test_a_write_cannot_be_added_to_the_allowlist(sql):
    bad = NamedQuery("wipe", "", sql, {}, "erp:read", 1)
    with pytest.raises(AllowlistError):
        load_allowlist((bad,))
