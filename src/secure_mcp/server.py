"""MCP surface: two read-only tools over the gateway.

Authentication happens in the SDK's bearer middleware, before any tool runs:
a request without a valid token gets HTTP 401. Inside a tool, the verified
token is read from the request context. If there is none (for example the
server was started over stdio, where there is no bearer header), the tools
refuse instead of falling back to an anonymous user.
"""

from __future__ import annotations

from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .gateway import Denied, Gateway, Principal
from .queries import SCOPE_READ
from .tokens import StoreVerifier

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def current_principal() -> Principal | None:
    token = get_access_token()
    if token is None:
        return None
    return Principal(
        subject=token.subject or token.client_id,
        client_id=token.client_id,
        scopes=frozenset(token.scopes),
    )


def build_server(gateway: Gateway, verifier: StoreVerifier, base_url: str, issuer_url: str) -> MCPServer:
    server = MCPServer(
        name="secure-erp-readonly",
        instructions=(
            "Read-only access to ERP data through named queries. "
            "Call list_queries to see what you may run, then run_query with a name and params."
        ),
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=f"{base_url}/mcp",
            required_scopes=[SCOPE_READ],
            # Refuse tokens whose resource is not this server (RFC 8707 audience).
            validate_token_resource=True,
        ),
    )

    @server.tool(annotations=READ_ONLY)
    async def list_queries() -> list[dict[str, Any]]:
        """List the named queries your token may run, with their parameters."""
        try:
            return gateway.visible_queries(current_principal())
        except Denied as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(annotations=READ_ONLY)
    async def run_query(name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one allowlisted query by name. No SQL text is accepted."""
        try:
            return gateway.run(current_principal(), name, params)
        except Denied as exc:
            raise ToolError(str(exc)) from exc

    return server
