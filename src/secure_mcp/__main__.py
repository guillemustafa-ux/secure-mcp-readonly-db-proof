"""Command line: create the demo database, issue or revoke tokens, serve.

    python -m secure_mcp init-db --db data/erp.sqlite
    python -m secure_mcp issue-token --tokens tokens.json --subject ana --scope erp:read \
        --resource http://127.0.0.1:8765/mcp
    python -m secure_mcp revoke --tokens tokens.json --subject ana
    python -m secure_mcp serve --db data/erp.sqlite --tokens tokens.json --audit audit.jsonl
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .audit import JsonlAuditSink
from .db import connect_readonly
from .gateway import Gateway
from .queries import load_allowlist
from .quota import SlidingWindowQuota
from .schema import create_database
from .server import build_server
from .tokens import StoreVerifier, TokenStore


def build_app(db: Path, tokens: Path, audit: Path, host: str, port: int, issuer_url: str,
              quota_limit: int, quota_window: float, hard_row_cap: int):
    base_url = f"http://{host}:{port}"
    gateway = Gateway(
        conn=connect_readonly(db),
        allowlist=load_allowlist(),
        quota=SlidingWindowQuota(quota_limit, quota_window),
        audit=JsonlAuditSink(audit),
        hard_row_cap=hard_row_cap,
    )
    server = build_server(gateway, StoreVerifier(TokenStore(tokens)), base_url, issuer_url)
    # Stateless: no server-side MCP sessions, so one token cannot exhaust a
    # session table that other users depend on.
    return server.streamable_http_app(host=host, stateless_http=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="secure_mcp")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-db", help="create the demo SQLite database")
    p_init.add_argument("--db", type=Path, default=Path("data/erp.sqlite"))

    p_issue = sub.add_parser("issue-token", help="issue a bearer token (printed once)")
    p_issue.add_argument("--tokens", type=Path, default=Path("tokens.json"))
    p_issue.add_argument("--subject", required=True)
    p_issue.add_argument("--scope", action="append", required=True)
    p_issue.add_argument("--ttl-hours", type=float, default=24)
    p_issue.add_argument("--resource", default="http://127.0.0.1:8765/mcp",
                         help="MCP URL of the server this token is valid for")
    p_issue.add_argument("--client-id", default="local-cli",
                         help="label for the client that will use the token (shown in the audit log)")

    p_revoke = sub.add_parser("revoke", help="revoke every token of a subject")
    p_revoke.add_argument("--tokens", type=Path, default=Path("tokens.json"))
    p_revoke.add_argument("--subject", required=True)

    p_serve = sub.add_parser("serve", help="serve MCP over streamable HTTP")
    p_serve.add_argument("--db", type=Path, default=Path("data/erp.sqlite"))
    p_serve.add_argument("--tokens", type=Path, default=Path("tokens.json"))
    p_serve.add_argument("--audit", type=Path, default=Path("audit.jsonl"))
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--issuer-url", default="https://idp.example.com",
                         help="authorization server advertised in the resource metadata")
    p_serve.add_argument("--quota-limit", type=int, default=60)
    p_serve.add_argument("--quota-window", type=float, default=60.0)
    p_serve.add_argument("--hard-row-cap", type=int, default=200)

    args = parser.parse_args(argv)
    if args.command == "init-db":
        print(f"created {create_database(args.db)}")
    elif args.command == "issue-token":
        token = TokenStore(args.tokens).issue(
            args.subject, args.scope, int(args.ttl_hours * 3600), args.resource, args.client_id
        )
        print("Token (shown once, store it now; only its SHA-256 is kept):")
        print(token)
    elif args.command == "revoke":
        print(f"revoked {TokenStore(args.tokens).revoke_subject(args.subject)} token(s)")
    elif args.command == "serve":
        import uvicorn

        app = build_app(args.db, args.tokens, args.audit, args.host, args.port, args.issuer_url,
                        args.quota_limit, args.quota_window, args.hard_row_cap)
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
