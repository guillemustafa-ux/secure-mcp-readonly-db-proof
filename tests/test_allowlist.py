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
        "PRAGMA writable_schema = 1",
        "ATTACH DATABASE 'x.db' AS x",
        "  insert into customers values (1)",
    ],
)
def test_lint_rejects_anything_but_one_select(sql):
    with pytest.raises(AllowlistError):
        check_statement(sql)


def test_lint_accepts_with_and_trailing_semicolon():
    check_statement("WITH a AS (SELECT 1 AS x) SELECT x FROM a;")


def test_duplicate_names_are_rejected():
    q = QUERIES[0]
    with pytest.raises(AllowlistError):
        load_allowlist((q, q))


def test_a_write_cannot_be_added_to_the_allowlist():
    bad = NamedQuery("wipe", "", "DELETE FROM invoices", {}, "erp:read", 1)
    with pytest.raises(AllowlistError):
        load_allowlist((bad,))
