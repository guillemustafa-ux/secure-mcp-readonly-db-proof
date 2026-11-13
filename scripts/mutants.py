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
