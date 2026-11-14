"""Mutation check: remove or weaken one guard at a time and confirm the suite fails.

    python scripts/mutants.py

Each mutant is a one-line change to a copy of the repo in a temporary
directory (the working tree is never touched). A mutant that leaves the
suite green means that guard has no test protecting it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(".venv", ".git", "__pycache__", ".pytest_cache", "data", "*.jsonl", "tokens.json")

MUTANTS = [
    ("db: file opened without mode=ro", "src/secure_mcp/db.py", '?mode=ro"', '"'),
    ("db: authorizer not installed", "src/secure_mcp/db.py", "conn.set_authorizer(_authorizer)", "pass"),
    ("db: payroll added to readable tables", "src/secure_mcp/db.py",
     '{"customers", "invoices", "invoice_lines"}', '{"customers", "invoices", "invoice_lines", "payroll"}'),
    ("queries: LIKE wildcards not escaped", "src/secure_mcp/queries.py",
     'prefix.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_")', "prefix"),
    ("params: bool accepted as int", "src/secure_mcp/params.py",
     "isinstance(value, bool) or not isinstance(value, int)", "not isinstance(value, int)"),
    ("params: unknown keys ignored", "src/secure_mcp/params.py", "    if unknown:\n", "    if False:\n"),
    ("gateway: scope not checked", "src/secure_mcp/gateway.py", "if query.scope not in principal.scopes:", "if False:"),
    ("gateway: quota not charged on run_query", "src/secure_mcp/gateway.py",
     "rate-limited too.\n        try:\n            self.quota.consume(principal.subject)",
     "rate-limited too.\n        try:\n            pass"),
    ("gateway: quota not charged on list_queries", "src/secure_mcp/gateway.py",
     'self.quota.consume(principal.subject)\n        except QuotaExceeded as exc:\n            self._audit(principal, "list_queries"',
     'pass\n        except QuotaExceeded as exc:\n            self._audit(principal, "list_queries"'),
    ("gateway: rows not capped", "src/secure_mcp/gateway.py",
     "rows = [dict(r) for r in fetched[:limit]]", "rows = [dict(r) for r in fetched]"),
    ("gateway: audit failure swallowed", "src/secure_mcp/gateway.py",
     'raise AuditUnavailable("audit log unavailable; request refused") from exc', "return"),
    ("gateway: sensitive values logged in clear", "src/secure_mcp/gateway.py",
     "(redact(v) if query.params[k].sensitive else v)", "v"),
    ("server: anonymous fallback without a token", "src/secure_mcp/server.py",
     "    if token is None:\n        return None",
     '    if token is None:\n        return Principal("anonymous", "", frozenset({"erp:read"}))'),
    ("server: token audience not checked", "src/secure_mcp/server.py",
     "validate_token_resource=True", "validate_token_resource=False"),
    ("server: base scope not required", "src/secure_mcp/server.py", "required_scopes=[SCOPE_READ],", "required_scopes=None,"),
    ("db: every SQL function allowed", "src/secure_mcp/db.py",
     'return sqlite3.SQLITE_OK if (arg2 or "").lower() in ALLOWED_FUNCTIONS else sqlite3.SQLITE_DENY',
     "return sqlite3.SQLITE_OK"),
    ("queries: lint misses WITH ... DELETE", "src/secure_mcp/queries.py",
     '    if _WRITE_WORDS.search(body):\n        raise AllowlistError("query must be read-only")', "    pass"),
    ("queries: lint misses WITH ... REPLACE", "src/secure_mcp/queries.py",
     r"(INSERT|UPDATE|DELETE|REPLACE|UPSERT", r"(INSERT|UPDATE|DELETE|UPSERT"),
    ("main: HTTP sessions kept on the server", "src/secure_mcp/__main__.py",
     "stateless_http=True", "stateless_http=False"),
    ("gateway: raw query name written to the log", "src/secure_mcp/gateway.py",
     '"query": query if isinstance(query, str) and query in self.allowlist else None,',
     '"query": query if isinstance(query, str) else None,'),
    ("gateway: list_queries ok not audited", "src/secure_mcp/gateway.py",
     'self._audit(principal, "list_queries", None, None, "ok", len(out), False, 0.0)', "pass"),
    ("gateway: database error not audited", "src/secure_mcp/gateway.py",
     'self._audit(principal, "run_query", name, logged, "error:database", 0, False, started)', "pass"),
    ("gateway: database error returned as an empty result", "src/secure_mcp/gateway.py",
     'raise Denied("database_error")', "fetched = []"),
    ("gateway: unknown query not audited", "src/secure_mcp/gateway.py",
     'raise deny("unknown_query")', 'raise Denied("unknown_query")'),
    ("gateway: quota refusal on run_query not audited", "src/secure_mcp/gateway.py",
     'raise deny("quota_exceeded", str(exc))', 'raise Denied("quota_exceeded", str(exc))'),
    ("gateway: client_id not logged", "src/secure_mcp/gateway.py",
     '"client_id": principal.client_id if principal else None,', '"client_id": None,'),
    ("audit: redaction is not a real hash", "src/secure_mcp/audit.py",
     'return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()',
     'return "sha256:" + str(value)[::-1]'),
    ("server: list_queries runs as anonymous without a token", "src/secure_mcp/server.py",
     "return gateway.visible_queries(current_principal())",
     'return gateway.visible_queries(current_principal() or Principal("anonymous", "", frozenset({"erp:read"})))'),
    ("tokens: expiry ignored", "src/secure_mcp/tokens.py", "if r.revoked or r.expires_at <= now:", "if r.revoked:"),
    ("tokens: raw token stored instead of its hash", "src/secure_mcp/tokens.py",
     "token_sha256=token_hash(token),", "token_sha256=token,"),
]


def suite_passes(workdir: Path) -> bool:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
        cwd=workdir, capture_output=True, text=True, timeout=600,
    )
    return result.returncode == 0


def fresh_copy(base: Path) -> Path:
    work = base / "work"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(REPO, work, ignore=IGNORE)
    return work


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="secure-mcp-mutants-"))
    try:
        if not suite_passes(fresh_copy(base)):
            print("baseline suite fails; fix it before running mutants")
            return 2
        survivors = []
        for label, rel, old, new in MUTANTS:
            work = fresh_copy(base)
            target = work / rel
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"anchor for '{label}' found {text.count(old)} times; update this script")
                return 2
            target.write_text(text.replace(old, new), encoding="utf-8")
            passed = suite_passes(work)
            print(f"{'SURVIVED' if passed else 'killed  '}  {label}")
            if passed:
                survivors.append(label)
        print(f"{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} mutants killed")
        return 1 if survivors else 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
