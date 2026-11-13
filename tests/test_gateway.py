import json

import pytest

from secure_mcp.gateway import AuditUnavailable, Denied
from secure_mcp.quota import SlidingWindowQuota

from conftest import FINANCE, READER, BrokenSink, count_rows


def test_happy_path_returns_rows_and_is_audited(make_gateway, sink):
    result = make_gateway().run(READER, "customer_by_id", {"customer_id": 3})
    assert result["row_count"] == 1
    assert result["rows"][0]["id"] == 3
    assert result["truncated"] is False
    assert sink.events[-1]["outcome"] == "ok"
    assert sink.events[-1]["subject"] == "ana"


def test_sql_in_a_text_param_is_data_not_code(make_gateway, db_path):
    payload = "Z' OR 'a' LIKE 'a"  # passes the character allowlist on purpose
    before = count_rows(db_path, "customers")
    result = make_gateway().run(READER, "customer_search", {"name_prefix": payload})
    assert result["rows"] == []
    assert count_rows(db_path, "customers") == before


def test_sql_in_an_enum_param_is_rejected(make_gateway):
    with pytest.raises(Denied) as exc:
        make_gateway().run(READER, "invoices_for_customer", {"customer_id": 1, "status": "open' OR '1'='1"})
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("prefix, expected", [("%", []), ("_", []), ("100%", ["100% Organic_Foods"])])
def test_like_wildcards_in_the_prefix_match_literally(make_gateway, prefix, expected):
    result = make_gateway().run(READER, "customer_search", {"name_prefix": prefix})
    assert [r["name"] for r in result["rows"]] == expected


def test_a_query_outside_the_token_scope_is_forbidden(make_gateway, sink):
    with pytest.raises(Denied) as exc:
        make_gateway().run(READER, "overdue_invoices", {"as_of": "2026-12-31"})
    assert exc.value.code == "forbidden"
    assert sink.events[-1]["outcome"] == "denied:forbidden"


def test_list_queries_only_shows_what_the_token_may_run(make_gateway):
    gw = make_gateway()
    reader_names = {q["name"] for q in gw.visible_queries(READER)}
    finance_names = {q["name"] for q in gw.visible_queries(FINANCE)}
    assert "overdue_invoices" not in reader_names
    assert {"overdue_invoices", "revenue_by_month"} <= finance_names


@pytest.mark.parametrize("name", ["drop_everything", 123, None, "customer_by_id; --"])
def test_unknown_query_names_are_refused(make_gateway, name):
    with pytest.raises(Denied) as exc:
        make_gateway().run(READER, name, {})
    assert exc.value.code == "unknown_query"


def test_no_principal_means_no_access(make_gateway, sink):
    gw = make_gateway()
    with pytest.raises(Denied) as exc:
        gw.run(None, "customer_by_id", {"customer_id": 1})
    assert exc.value.code == "unauthenticated"
    with pytest.raises(Denied):
        gw.visible_queries(None)
    assert [e["outcome"] for e in sink.events] == ["denied:unauthenticated"] * 2


def test_per_query_row_cap_and_truncation_flag(make_gateway):
    result = make_gateway().run(FINANCE, "overdue_invoices", {"as_of": "2026-12-31"})
    assert result["row_count"] == 100
    assert result["truncated"] is True


def test_server_wide_hard_cap_wins_over_the_query_cap(make_gateway):
    result = make_gateway(hard_row_cap=10).run(FINANCE, "overdue_invoices", {"as_of": "2026-12-31"})
    assert result["row_count"] == 10
    assert result["truncated"] is True


def test_quota_blocks_then_recovers_after_the_window(make_gateway):
    now = [0.0]
    gw = make_gateway(quota=SlidingWindowQuota(3, 60, clock=lambda: now[0]))
    for _ in range(3):
        gw.run(READER, "customer_by_id", {"customer_id": 1})
    with pytest.raises(Denied) as exc:
        gw.run(READER, "customer_by_id", {"customer_id": 1})
    assert exc.value.code == "quota_exceeded"
    now[0] = 61.0
    assert gw.run(READER, "customer_by_id", {"customer_id": 1})["row_count"] == 1


def test_quota_is_per_user(make_gateway):
    gw = make_gateway(quota=SlidingWindowQuota(1, 60, clock=lambda: 0.0))
    gw.run(READER, "customer_by_id", {"customer_id": 1})
    assert gw.run(FINANCE, "customer_by_id", {"customer_id": 1})["row_count"] == 1


def test_probing_unknown_queries_also_spends_quota(make_gateway):
    gw = make_gateway(quota=SlidingWindowQuota(2, 60, clock=lambda: 0.0))
    for _ in range(2):
        with pytest.raises(Denied):
            gw.run(READER, "guess", {})
    with pytest.raises(Denied) as exc:
        gw.run(READER, "customer_by_id", {"customer_id": 1})
    assert exc.value.code == "quota_exceeded"


def test_listing_queries_spends_quota_too(make_gateway, sink):
    gw = make_gateway(quota=SlidingWindowQuota(1, 60, clock=lambda: 0.0))
    gw.visible_queries(READER)
    with pytest.raises(Denied) as exc:
        gw.visible_queries(READER)
    assert exc.value.code == "quota_exceeded"
    assert sink.events[-1]["outcome"] == "denied:quota_exceeded"


def test_every_call_is_audited_without_rows_or_sensitive_values(make_gateway, sink):
    gw = make_gateway()
    gw.run(READER, "customer_search", {"name_prefix": "Acme"})
    with pytest.raises(Denied):
        gw.run(READER, "overdue_invoices", {"as_of": "2026-12-31"})
    with pytest.raises(Denied):
        gw.run(READER, "customer_by_id", {"customer_id": "x"})
    assert [e["outcome"] for e in sink.events] == ["ok", "denied:forbidden", "denied:invalid_params"]
    first = sink.events[0]
    assert first["params"]["name_prefix"].startswith("sha256:")
    dumped = json.dumps(sink.events)
    assert "Acme" not in dumped  # neither the sensitive value nor any returned row


def test_if_the_audit_line_cannot_be_written_no_data_is_returned(make_gateway):
    gw = make_gateway(audit=BrokenSink())
    with pytest.raises(AuditUnavailable):
        gw.run(READER, "customer_by_id", {"customer_id": 1})
