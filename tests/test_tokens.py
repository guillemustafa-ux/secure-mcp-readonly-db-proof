import asyncio
import time

from secure_mcp.tokens import StoreVerifier, TokenStore, token_hash


def test_only_the_hash_is_stored(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], ttl_seconds=3600)
    text = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert token not in text
    assert token_hash(token) in text


def test_lookup_accepts_the_right_token_only(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], ttl_seconds=3600)
    assert store.lookup(token).subject == "ana"
    assert store.lookup(token + "x") is None
    assert store.lookup("") is None


def test_expired_tokens_are_refused(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], ttl_seconds=60)
    assert store.lookup(token, now=time.time() + 61) is None


def test_revoked_tokens_are_refused(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("ana", ["erp:read"], ttl_seconds=3600)
    assert store.revoke_subject("ana") == 1
    assert store.lookup(token) is None


def test_verifier_maps_the_record_to_an_mcp_access_token(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.issue("fin", ["erp:read", "erp:finance"], ttl_seconds=3600)
    verifier = StoreVerifier(store, resource="http://127.0.0.1:1/mcp")
    access = asyncio.run(verifier.verify_token(token))
    assert access.subject == "fin"
    assert set(access.scopes) == {"erp:read", "erp:finance"}
    assert asyncio.run(verifier.verify_token("wrong")) is None
