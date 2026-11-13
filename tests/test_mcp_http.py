"""End to end over real HTTP: SDK bearer middleware, MCP client, audit file."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from secure_mcp.__main__ import build_app
from secure_mcp.audit import JsonlAuditSink
from secure_mcp.db import connect_readonly
from secure_mcp.gateway import Gateway
from secure_mcp.queries import load_allowlist
from secure_mcp.quota import SlidingWindowQuota
from secure_mcp.server import build_server
from secure_mcp.tokens import StoreVerifier, TokenStore

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live(tmp_path_factory, db_path):
    tmp = tmp_path_factory.mktemp("live")
    store = TokenStore(tmp / "tokens.json")
    tokens = {
        "reader": store.issue("ana", ["erp:read"], 3600),
        "finance": store.issue("fin", ["erp:read", "erp:finance"], 3600),
        "no_read": store.issue("eve", ["erp:finance"], 3600),
    }
    port = _free_port()
    app = build_app(db_path, tmp / "tokens.json", tmp / "audit.jsonl", "127.0.0.1", port,
                    "https://idp.example.com", quota_limit=100, quota_window=60, hard_row_cap=200)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("server did not start")
        time.sleep(0.05)
    yield {"url": f"http://127.0.0.1:{port}/mcp", "tokens": tokens, "audit": tmp / "audit.jsonl"}
    server.should_exit = True
    thread.join(timeout=5)


def _post(url, token=None):
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx2.post(url, json=INIT, headers=headers, timeout=10)


@pytest.mark.parametrize("token", [None, "not-a-real-token"])
def test_requests_without_a_valid_token_get_401(live, token):
    assert _post(live["url"], token).status_code == 401


def test_a_token_without_the_base_scope_is_refused(live):
    assert _post(live["url"], live["tokens"]["no_read"]).status_code == 403


def test_a_valid_token_for_another_resource_is_refused(live, db_path, tmp_path):
    """Same token store, but the verifier says the token was issued for another server."""
    port = _free_port()
    store_path = tmp_path / "tokens.json"
    token = TokenStore(store_path).issue("ana", ["erp:read"], 3600)
    gateway = Gateway(connect_readonly(db_path), load_allowlist(), SlidingWindowQuota(10, 60),
                      JsonlAuditSink(tmp_path / "audit.jsonl"))
    wrong_audience = StoreVerifier(TokenStore(store_path), resource="https://other-server.example.com/mcp")
    app = build_server(gateway, wrong_audience, f"http://127.0.0.1:{port}", "https://idp.example.com") \
        .streamable_http_app(host="127.0.0.1")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started:
            assert time.time() < deadline
            time.sleep(0.05)
        assert _post(f"http://127.0.0.1:{port}/mcp", token).status_code == 401
    finally:
        server.should_exit = True
        thread.join(timeout=5)


async def _session(url, token, fn):
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    async with Client(streamable_http_client(url, http_client=http)) as client:
        return await fn(client)


def _run(live, who, fn):
    return asyncio.run(_session(live["url"], live["tokens"][who], fn))


def test_tools_are_marked_read_only(live):
    async def fn(client):
        return (await client.list_tools()).tools

    tools = {t.name: t for t in _run(live, "reader", fn)}
    assert set(tools) == {"list_queries", "run_query"}
    assert all(t.annotations.read_only_hint for t in tools.values())


def test_reader_sees_and_runs_only_read_queries(live):
    async def fn(client):
        listed = await client.call_tool("list_queries", {})
        ok = await client.call_tool("run_query", {"name": "customer_by_id", "params": {"customer_id": 3}})
        denied = await client.call_tool("run_query", {"name": "overdue_invoices", "params": {"as_of": "2026-12-31"}})
        return listed, ok, denied

    listed, ok, denied = _run(live, "reader", fn)
    names = {q["name"] for q in listed.structured_content["result"]}
    assert "overdue_invoices" not in names
    assert ok.is_error is False
    assert ok.structured_content["rows"][0]["id"] == 3
    assert denied.is_error is True
    assert "forbidden" in denied.content[0].text


def test_finance_token_runs_finance_queries(live):
    async def fn(client):
        return await client.call_tool("run_query", {"name": "overdue_invoices", "params": {"as_of": "2026-12-31"}})

    result = _run(live, "finance", fn)
    assert result.is_error is False
    assert result.structured_content["truncated"] is True


def test_http_calls_land_in_the_audit_file_without_the_token(live):
    async def fn(client):
        return await client.call_tool("run_query", {"name": "customer_by_id", "params": {"customer_id": 5}})

    _run(live, "reader", fn)
    text = live["audit"].read_text(encoding="utf-8")
    events = [json.loads(line) for line in text.splitlines()]
    assert any(e["subject"] == "ana" and e["params"] == {"customer_id": 5} and e["outcome"] == "ok" for e in events)
    for token in live["tokens"].values():
        assert token not in text


def test_without_a_bearer_context_the_tools_fail_closed(db_path, tmp_path):
    """In-process client, no HTTP and so no token: tools must refuse, not run anonymously."""
    gateway = Gateway(connect_readonly(db_path), load_allowlist(), SlidingWindowQuota(10, 60),
                      JsonlAuditSink(tmp_path / "audit.jsonl"))
    server = build_server(gateway, StoreVerifier(TokenStore(tmp_path / "t.json")),
                          "http://127.0.0.1:1", "https://idp.example.com")

    async def fn():
        async with Client(server) as client:
            return await client.call_tool("run_query", {"name": "customer_by_id", "params": {"customer_id": 1}})

    result = asyncio.run(fn())
    assert result.is_error is True
    assert "unauthenticated" in result.content[0].text
