"""Per-user bearer tokens, stored only as SHA-256 hashes.

The raw token is shown once when it is issued and never written to disk.
Each token is issued for one server (its MCP URL, the RFC 8707 resource), so
two servers sharing a token file still refuse each other's tokens.

This store is the local stand-in for an identity provider: ``StoreVerifier``
implements the MCP SDK's ``TokenVerifier`` protocol, which is where an
OAuth/JWT check against a real IdP would go instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from mcp.server.auth.provider import AccessToken


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TokenRecord:
    token_sha256: str
    subject: str
    client_id: str
    scopes: tuple[str, ...]
    expires_at: int  # unix seconds
    resource: str  # MCP URL of the one server this token is valid for
    revoked: bool = False


class TokenStore:
    def __init__(self, path: Path):
        self.path = path

    def _load(self) -> list[TokenRecord]:
        if not self.path.exists():
            return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return [TokenRecord(**{**r, "scopes": tuple(r["scopes"])}) for r in raw]

    def _save(self, records: list[TokenRecord]) -> None:
        data = [{**asdict(r), "scopes": list(r.scopes)} for r in records]
        # Write a temp file and swap it in, so a reader never sees half a file.
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def issue(
        self,
        subject: str,
        scopes: list[str],
        ttl_seconds: int,
        resource: str,
        client_id: str = "local-cli",
    ) -> str:
        token = secrets.token_urlsafe(32)
        record = TokenRecord(
            token_sha256=token_hash(token),
            subject=subject,
            client_id=client_id,
            scopes=tuple(sorted(set(scopes))),
            expires_at=int(time.time()) + ttl_seconds,
            resource=resource,
        )
        self._save(self._load() + [record])
        return token

    def revoke_subject(self, subject: str) -> int:
        records = self._load()
        count = 0
        updated = []
        for r in records:
            if r.subject == subject and not r.revoked:
                r = TokenRecord(**{**asdict(r), "revoked": True})
                count += 1
            updated.append(r)
        self._save(updated)
        return count

    def lookup(self, token: str, now: float | None = None) -> TokenRecord | None:
        """Find a live record for a presented token.

        Lookup is by hash, so the comparison never touches the raw secret
        and does not leak how many leading characters matched.
        """
        if not token:
            return None
        digest = token_hash(token)
        now = time.time() if now is None else now
        for r in self._load():
            if r.token_sha256 == digest:
                if r.revoked or r.expires_at <= now:
                    return None
                return r
        return None


class StoreVerifier:
    """MCP ``TokenVerifier`` backed by the local token store.

    It reports the resource the token was issued for; the SDK middleware
    (``validate_token_resource=True`` in server.py) refuses the request when
    that is not this server's URL.
    """

    def __init__(self, store: TokenStore):
        self.store = store

    async def verify_token(self, token: str) -> AccessToken | None:
        record = self.store.lookup(token)
        if record is None:
            return None
        return AccessToken(
            token=token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=record.expires_at,
            resource=record.resource,
            subject=record.subject,
        )
