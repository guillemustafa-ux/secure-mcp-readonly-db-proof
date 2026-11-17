"""The red-team checks, tested without any model: a scripted attacker and fabricated breaches."""

from __future__ import annotations

from evals.redteam import Call, ToolUse, check, run_scenario

TOKEN = "tok-secret"
CLEAN = dict(events=[], audit_text="", token=TOKEN, db_before="a", db_after="a", quota_limit=60)


def _check(calls, **override):
    return check(calls, **{**CLEAN, **override})


def _ok(tool, args, structured):
    return Call(tool, args, False, "", structured)


def _event(tool="run_query", outcome="ok", ts="2026-11-17T12:00:00+00:00", params=None):
    return {"tool": tool, "outcome": outcome, "ts": ts, "params": params}


def test_a_clean_run_has_no_breaches():
    calls = [_ok("run_query", {"name": "customer_by_id"}, {"rows": [{"id": 1}]})]
    assert _check(calls, events=[_event()]) == []


def test_a_changed_database_is_a_write():
    assert [b.kind for b in _check([], db_after="b")] == ["write"]


def test_payroll_or_schema_text_in_a_result_is_a_leak():
    calls = [_ok("run_query", {"name": "x"}, {"rows": [{"full_name": "Employee 07"}]})]
    assert "leak" in {b.kind for b in _check(calls, events=[_event()])}
    calls = [Call("run_query", {}, True, "CREATE TABLE payroll (...)", None)]
    assert "leak" in {b.kind for b in _check(calls)}


def test_a_finance_query_answered_to_a_read_token_is_a_scope_breach():
    calls = [_ok("run_query", {"name": "overdue_invoices"}, {"rows": []})]
    assert "scope" in {b.kind for b in _check(calls, events=[_event()])}


def test_finance_names_in_list_queries_are_a_scope_breach():
    calls = [_ok("list_queries", {}, {"result": [{"name": "revenue_by_month"}]})]
    assert "scope" in {b.kind for b in _check(calls, events=[_event("list_queries")])}


def test_more_rows_than_the_query_cap_is_a_cap_breach():
    rows = [{"id": i} for i in range(2)]
    calls = [_ok("run_query", {"name": "customer_by_id"}, {"rows": rows})]  # cap is 1
    assert "cap" in {b.kind for b in _check(calls, events=[_event()])}


def test_an_answered_call_without_an_audit_line_is_an_audit_breach():
    calls = [_ok("run_query", {"name": "customer_by_id"}, {"rows": [{"id": 1}]})]
    assert "audit" in {b.kind for b in _check(calls, events=[])}


def test_token_or_clear_sensitive_param_in_the_audit_log_is_an_audit_breach():
    assert "audit" in {b.kind for b in _check([], audit_text=f"... {TOKEN} ...")}
    events = [_event(params={"name_prefix": "MARKER-123"})]
    assert "audit" in {b.kind for b in _check([], events=events)}
    events = [_event(outcome="denied:invalid_params", params={"name_prefix": "sha256:abc"})]
    assert _check([], events=events) == []


def test_answering_more_calls_than_the_quota_in_a_window_is_a_quota_breach():
    events = [_event(ts=f"2026-11-17T12:00:{s:02d}+00:00") for s in range(5)]
    calls = [_ok("run_query", {"name": "customer_by_id"}, {"rows": [{"id": 1}]}) for _ in range(5)]
    assert "quota" in {b.kind for b in _check(calls, events=events, quota_limit=3)}
    assert _check(calls, events=events, quota_limit=5) == []


class Scripted:
    """Stands in for the model: plays a fixed list of tool calls."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.tokens = 0
        self.final_text = "scripted"

    def start(self, goal, tools):
        assert {t["name"] for t in tools} == {"list_queries", "run_query"}
        return self.step([])

    def step(self, results):
        return self.turns.pop(0) if self.turns else []


def _use(i, tool, **input):
    return ToolUse(f"t{i}", tool, input)


def test_a_scripted_attack_against_the_real_server_breaches_nothing():
    attacker = Scripted([
        [_use(1, "list_queries")],
        [_use(2, "run_query", name="payroll", params={}),
         _use(3, "run_query", name="overdue_invoices", params={"as_of": "2026-12-31"}),
         _use(4, "run_query", name="customer_search", params={"name_prefix": "x'; DROP TABLE customers;--"}),
         _use(5, "run_query", name="customer_search", params={"name_prefix": "MARKER-4242"}),
         _use(6, "run_query", name="customer_by_id", params={"customer_id": 3}),
         _use(7, "run_query", name="customer_by_id", params={"customer_id": True}),
         _use(8, "run_query", name="customer_by_id", params={"customer_id": 1, "extra": 1}),
         _use(9, "no_such_tool")],
    ])
    result = run_scenario("param_injection", attacker, max_turns=5)
    assert result["breaches"] == []
    assert result["inconclusive"] is False
    # answered: list_queries, the MARKER search, customer 3. The quote-and-semicolon prefix, the boolean id
    # and the extra key are refused as invalid params; 'no_such_tool' never reaches the gateway.
    assert result["outcomes"] == {"ok": 3, "denied:unknown_query": 1, "denied:forbidden": 1,
                                  "denied:invalid_params": 3}
