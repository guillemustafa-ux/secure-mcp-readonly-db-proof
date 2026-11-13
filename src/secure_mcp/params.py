"""Parameter specs and validation for allowlisted queries.

Every value an MCP client sends is checked against a spec before it reaches
SQL. Values are always bound as parameters, never formatted into the query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any


class ParamError(ValueError):
    """A parameter failed validation. The message is safe to show to the caller."""


@dataclass(frozen=True)
class IntParam:
    min_value: int
    max_value: int
    sensitive: bool = False

    def validate(self, name: str, value: Any) -> int:
        # bool is a subclass of int in Python; True must not pass as 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ParamError(f"{name} must be an integer")
        if not self.min_value <= value <= self.max_value:
            raise ParamError(f"{name} must be between {self.min_value} and {self.max_value}")
        return value


@dataclass(frozen=True)
class TextParam:
    max_length: int
    pattern: str
    sensitive: bool = False

    def validate(self, name: str, value: Any) -> str:
        if not isinstance(value, str):
            raise ParamError(f"{name} must be a string")
        if not 1 <= len(value) <= self.max_length:
            raise ParamError(f"{name} must be 1 to {self.max_length} characters")
        if not re.fullmatch(self.pattern, value):
            raise ParamError(f"{name} contains characters that are not allowed")
        return value


@dataclass(frozen=True)
class EnumParam:
    choices: tuple[str, ...]
    sensitive: bool = False

    def validate(self, name: str, value: Any) -> str:
        if not isinstance(value, str) or value not in self.choices:
            raise ParamError(f"{name} must be one of: {', '.join(self.choices)}")
        return value


@dataclass(frozen=True)
class DateParam:
    min_value: date = field(default=date(2000, 1, 1))
    max_value: date = field(default=date(2100, 12, 31))
    sensitive: bool = False

    def validate(self, name: str, value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ParamError(f"{name} must be a date in YYYY-MM-DD format")
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ParamError(f"{name} is not a valid date") from exc
        if not self.min_value <= parsed <= self.max_value:
            raise ParamError(f"{name} is out of range")
        return parsed.isoformat()


ParamSpec = IntParam | TextParam | EnumParam | DateParam


def validate_params(specs: dict[str, ParamSpec], supplied: Any) -> dict[str, Any]:
    """Return validated values, or raise ParamError.

    Unknown keys are rejected rather than ignored, so a typo or a probing
    client never runs a query with a parameter silently dropped.
    """
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, dict):
        raise ParamError("params must be an object")
    unknown = sorted(set(supplied) - set(specs))
    if unknown:
        raise ParamError(f"unknown parameter(s): {', '.join(map(str, unknown))}")
    missing = sorted(set(specs) - set(supplied))
    if missing:
        raise ParamError(f"missing parameter(s): {', '.join(missing)}")
    return {name: spec.validate(name, supplied[name]) for name, spec in specs.items()}
