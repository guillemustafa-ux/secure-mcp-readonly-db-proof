import asyncio
import time

from secure_mcp.tokens import StoreVerifier, TokenStore, token_hash

RESOURCE = "http://127.0.0.1:8765/mcp"


def test_only_the_hash_is_stored(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], 3600, RESOURCE)
    text = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert token not in text
    assert token_hash(token) in text


def test_lookup_accepts_the_right_token_only(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], 3600, RESOURCE)
    assert store.lookup(token).subject == "ana"
    assert store.lookup(token + "x") is None
    assert store.lookup("") is None


def test_expired_tokens_are_refused(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], 60, RESOURCE)
    assert store.lookup(token, now=time.time() + 61) is None


def test_revoked_tokens_are_refused(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], 3600, RESOURCE)
    assert store.revoke_subject("ana") == 1
    assert store.lookup(token) is None


def test_saving_leaves_no_temp_file_behind(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.issue("ana", ["erp:read"], 3600, RESOURCE)
    store.revoke_subject("ana")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tokens.json"]


def test_verifier_maps_the_record_to_an_mcp_access_token(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("fin", ["erp:read", "erp:finance"], 3600, RESOURCE, client_id="claude-desktop")
    access = asyncio.run(StoreVerifier(store).verify_token(token))
    assert access.subject == "fin"
    assert access.client_id == "claude-desktop"
    assert access.resource == RESOURCE
    assert set(access.scopes) == {"erp:read", "erp:finance"}
    assert asyncio.run(StoreVerifier(store).verify_token("wrong")) is None
