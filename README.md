# secure-mcp-readonly-db-proof

A read-only MCP server that lets an AI agent query a business database over MCP. Any client that
speaks streamable HTTP and can send a bearer header can use it; the client exercised here is the
MCP Python SDK's own. The agent can't write, can't read tables you didn't expose and can't pull
unlimited rows. Every tool call that reaches the gateway is recorded, including the ones it
refused.

The database is a small synthetic ERP in SQLite (customers, invoices, invoice lines and a
`payroll` table the agent must never see). The guards are the part that carries over to a real
system. [Moving to SQL Server, Postgres or an identity provider](#moving-to-sql-server-postgres-or-an-identity-provider)
lists what changes.

## What the agent can and cannot do

| The agent can | The agent cannot |
| --- | --- |
| List the named queries its token allows | Send SQL text (no tool accepts it) |
| Run one of those queries with validated parameters | Run a query outside its token's scope |
| Get up to the query's row cap, with a `truncated` flag | Write, `ATTACH`, `PRAGMA`, or read `payroll` / `sqlite_master` |
| | Call anything without a valid, unexpired bearer token |
| | Use a token issued for another server, even one that shares the same token file |
| | Exceed its per-user call quota |

## The guards, in the order a request meets them

| # | Guard | Where | Proven by |
| --- | --- | --- | --- |
| 1 | **Bearer token per user**, checked by the MCP SDK's middleware before any tool runs: no token or a bad one gets HTTP 401, a token without the base scope gets 403, a token issued for another server gets 401 | `tokens.py`, `server.py` | `test_mcp_http.py` |
| 2 | **Tokens stored as SHA-256 only**, each bound to the URL of one server, with expiry and revocation; the raw token is printed once at issue, and the token file is replaced atomically | `tokens.py` | `test_tokens.py` |
| 3 | **Fail closed**: if a tool runs without a verified token, it refuses instead of treating the caller as anonymous. Tested in-process for both tools; stdio takes the same path, since there is no bearer middleware there either | `server.py` | `test_without_a_bearer_context_the_tools_fail_closed` |
| 4 | **Per-user quota** (sliding window) on both tools, charged before the query name is looked up, so probing is rate-limited too | `quota.py`, `gateway.py` | `test_gateway.py` |
| 5 | **Named-query allowlist**: the only SQL that can run is in `queries.py`. At load time each entry is linted to be a single statement that starts with `SELECT` or `WITH` and has no write keyword. That lint reads text; guard 9 is what stops a write at runtime | `queries.py` | `test_allowlist.py` |
| 6 | **Scope per query** (`erp:read`, `erp:finance`); `list_queries` only shows what the token may run | `queries.py`, `gateway.py` | `test_gateway.py`, `test_mcp_http.py` |
| 7 | **Parameter validation**: type, range, enum, length and a character allowlist; unknown keys are rejected, `True` is not accepted as `1` | `params.py` | `test_params.py` |
| 8 | **Bound parameters only**; `LIKE` wildcards in a search prefix are escaped, so `%` matches a literal `%` | `queries.py` | `test_gateway.py` |
| 9 | **Read-only database, two independent layers**: the file is opened with SQLite's `mode=ro`, and an authorizer allows only reads of three tables and a short list of functions (no writes, `ATTACH`, `PRAGMA`, `payroll`, `sqlite_master`, or functions such as `hex`). Each layer is tested with the other one removed | `db.py` | `test_database_guards.py` |
| 10 | **Row caps**: per query, plus a server-wide hard cap that wins if it is lower; the result says when it was truncated | `gateway.py` | `test_gateway.py` |
| 11 | **Audit log**: one JSON line per tool call that reaches the gateway, allowed or denied, with who (subject and client id), what and the outcome. Only allowlisted query names are written, parameters marked sensitive are stored as a SHA-256, and no token or returned row is written. **If the line cannot be written, the caller gets an error and no data** | `audit.py`, `gateway.py` | `test_gateway.py`, `test_mcp_http.py` |

Both tools are also annotated `readOnlyHint`. The HTTP app runs in the SDK's stateless mode, so
there are no server-side MCP sessions to fill up.

## Evidence

```bash
python -m pytest                 # 82 passed
python scripts/mutants.py        # 28 of 28 mutants killed
```

`scripts/mutants.py` copies the repo to a temporary directory and removes or weakens one guard at
a time, 28 small changes in all. Among them: drop `mode=ro`, drop the authorizer, allow every SQL
function, make `payroll` readable, let the lint miss `WITH … DELETE`, skip the scope check or the
quota, stop auditing a given outcome, write the raw query name or sensitive values to the log,
accept expired tokens, fall back to an anonymous user. It runs the suite against each change.
Every mutant makes at least one test fail, which means no guard in that list is there without a
test that notices its absence.

The HTTP tests start the real server with uvicorn and talk to it with the MCP SDK's client over
streamable HTTP, including a second server that shares the token file and must refuse the first
server's tokens.

## Audit log, as written

Two calls by the same user (token issued with the default `--client-id local-cli`): a search that
ran, then a finance query her token doesn't allow.

```json
{"client_id": "local-cli", "duration_ms": 0.43, "outcome": "ok", "params": {"name_prefix": "sha256:8d4f6c2a5c4e4b94b3dbaa65808d2325060f4d4b6ac32eb11e1a423f1ddf0a5a"}, "query": "customer_search", "rows": 3, "subject": "ana", "tool": "run_query", "truncated": false, "ts": "2026-11-13T18:29:58.417+00:00"}
{"client_id": "local-cli", "duration_ms": 0.03, "outcome": "denied:forbidden", "params": null, "query": "overdue_invoices", "rows": 0, "subject": "ana", "tool": "run_query", "truncated": false, "ts": "2026-11-13T18:29:58.417+00:00"}
```

Parameters are logged once they have passed validation. A call the gateway refuses before that
step (no verified identity, quota, unknown query, scope, invalid parameters) logs `"params": null`.

Requests the SDK rejects before a tool runs are not in this log: HTTP 401 and 403, arguments that
do not match the tool schema, and unknown tool names.

## Quick start

Tested on Python 3.13 with `mcp` 2.3.0 (pinned in `pyproject.toml`).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m secure_mcp init-db --db data/erp.sqlite
python -m secure_mcp issue-token --tokens tokens.json --subject ana --scope erp:read
python -m secure_mcp issue-token --tokens tokens.json --subject fin --scope erp:read --scope erp:finance
python -m secure_mcp serve --db data/erp.sqlite --tokens tokens.json --audit audit.jsonl
```

`issue-token` binds each token to `--resource`, which defaults to the URL `serve` listens on with
its defaults, `http://127.0.0.1:8765/mcp`. If you serve on another host or port, issue the tokens
with that URL. Connect any MCP client that speaks streamable HTTP and can send an
`Authorization: Bearer <token>` header. With the Python SDK:

```python
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
async with Client(streamable_http_client("http://127.0.0.1:8765/mcp", http_client=http)) as client:
    print(await client.call_tool("list_queries", {}))
    print(await client.call_tool("run_query", {"name": "customer_by_id", "params": {"customer_id": 3}}))
```

Revoke a user with `python -m secure_mcp revoke --tokens tokens.json --subject ana`.

## Moving to SQL Server, Postgres or an identity provider

These are the swap points. None of them is implemented or tested here.

- **Database engine.** Besides the demo seed (`schema.py`, `init-db`), three places in the
  request path know the engine is SQLite: `db.py` (connection and authorizer), `gateway.py`
  (`conn.execute` with `:name` bindings, rows turned into dicts, the `sqlite3` error type) and
  the SQL text in `queries.py` (`:name` placeholders, `substr`, `LIKE … ESCAPE`). Moving engines
  means a new driver in `db.py`, those details in `gateway.py`, possibly another placeholder
  style (pyodbc takes `?`), and a review of each allowlisted query. The SQLite authorizer has no
  direct equivalent elsewhere, so on SQL Server or Postgres the second read-only layer becomes a
  database login that only has `SELECT` on the views or schemas you expose. Parameter
  validation, scopes, row caps, quota and audit carry over as they are.
- **Identity provider / OAuth.** `StoreVerifier` implements the SDK's `TokenVerifier` protocol.
  The main change is a verifier that validates JWTs from your IdP (signature, expiry, audience)
  and maps their claims to the `erp:*` scopes, plus pointing `--issuer-url` at that IdP. The tools
  read the identity from the verified token and do not care where it came from.
- **Quota across replicas.** The quota is in memory, per process. Several replicas need a shared
  counter (Redis or the database) behind the same `consume()` call.
- **Audit retention.** Ship the JSON lines to write-once storage or a log pipeline.

## Limits: what this repo does not show

- It runs on SQLite with synthetic data. It has not been run against SQL Server, Postgres or a
  real ERP, and it has not run in production.
- There is no OAuth authorization flow. Tokens come from a local CLI, and `--issuer-url`
  defaults to a placeholder (`https://idp.example.com`) until you point it at a real IdP.
- No TLS. Put it behind a reverse proxy that terminates HTTPS before exposing it beyond localhost.
- The audit file is append-only by convention, not tamper-proof.
- Sensitive parameters are hashed with plain SHA-256. That keeps them out of casual reading, but
  a short value such as a customer name can be recovered by hashing guesses; a keyed HMAC is the
  stronger option.
- A query outside the token's scope is refused as `forbidden`, while an unknown name is refused
  as `unknown_query`, so a reader can tell which query names exist.
- The row cap counts rows, not bytes; a query returning very wide rows needs its own column list
  kept small (the allowlist already names columns explicitly).
- The quota resets when the process restarts.
- This is a reference implementation with tests, not a penetration test or a security audit of
  your system.

## Layout

```text
src/secure_mcp/
  server.py    MCP tools (list_queries, run_query) and SDK auth settings
  gateway.py   the guards in order, audit on every outcome
  queries.py   the allowlist: named queries, scopes, row caps
  params.py    parameter specs and validation
  db.py        read-only connection and SQLite authorizer
  tokens.py    hashed token store and the TokenVerifier
  quota.py     per-user sliding-window quota
  audit.py     JSON-lines audit sink
  schema.py    synthetic ERP schema and seed
tests/         82 tests, including real HTTP end to end
scripts/mutants.py   mutation check over 28 guard changes
```

## License

MIT. See [LICENSE](LICENSE).
