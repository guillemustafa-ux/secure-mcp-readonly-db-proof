"""Append-only audit log, one JSON line per tool call (allowed or denied).

What it records: who (subject and client id), which tool and query, the
parameters (values marked sensitive are replaced by a SHA-256), the outcome,
rows returned, whether the result was truncated, and how long it took.
What it never records: the bearer token or the rows themselves.

The log is append-only by convention, not tamper-proof: anyone with write
access to the file can edit it. Shipping lines to a write-once store is the
production step.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


class AuditSink(Protocol):
    def write(self, event: dict[str, Any]) -> None: ...


class JsonlAuditSink:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()


def redact(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
