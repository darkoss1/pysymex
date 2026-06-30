# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Public issue and evidence helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sized
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import TYPE_CHECKING, TypeAlias, cast

from pysymex._internal.analysis.detectors.detector.types import Issue, Severity
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.verified.types import ArithmeticIssue

if TYPE_CHECKING:
    IssueLike: TypeAlias = Issue | ContractIssue | ArithmeticIssue | Mapping[str, object]
else:
    IssueLike: TypeAlias = object


def data(issue: object) -> dict[str, object]:
    """Return a JSON-friendly dictionary for any public issue-like value."""
    if isinstance(issue, Mapping):
        return _mapping_to_dict(cast("Mapping[object, object]", issue))

    to_dict_method = getattr(issue, "to_dict", None)
    if callable(to_dict_method):
        raw = to_dict_method()
        if isinstance(raw, Mapping):
            return _mapping_to_dict(cast("Mapping[object, object]", raw))

    if is_dataclass(issue) and not isinstance(issue, type):
        return {
            field.name: _serialize(getattr(issue, field.name))
            for field in fields(issue)
        }

    return {
        "kind": _enum_or_string(getattr(issue, "kind", type(issue).__name__)),
        "message": str(getattr(issue, "message", issue)),
    }


def records(values: Iterable[object]) -> list[dict[str, object]]:
    """Return JSON-friendly dictionaries for an issue collection."""
    return [data(issue) for issue in values]


def render(issue: object) -> str:
    """Return a human-readable rendering for one issue-like value."""
    format_method = getattr(issue, "format", None)
    if callable(format_method):
        return str(format_method()).strip()

    issue_data = data(issue)
    kind = str(issue_data.get("kind") or issue_data.get("type") or "Issue")
    message = str(issue_data.get("message") or "")
    location = _location_from_dict(issue_data)
    if location:
        return f"[{kind}] {location}: {message}"
    return f"[{kind}] {message}"


def count(values: Iterable[object]) -> int:
    """Return the number of issue-like values in an iterable."""
    if isinstance(values, Sized):
        return len(values)
    return sum(1 for _ in values)


def found(values: Iterable[object]) -> bool:
    """Return whether an issue collection contains at least one finding."""
    return any(True for _ in values)


def _serialize(value: object) -> object:
    """Convert common result fields into JSON-friendly values."""
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, Mapping):
        return _mapping_to_dict(cast("Mapping[object, object]", value))
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in cast("Iterable[object]", value)]
    if isinstance(value, (set, frozenset)):
        return sorted((_serialize(item) for item in cast("Iterable[object]", value)), key=repr)
    to_dict_method = getattr(value, "to_dict", None)
    if callable(to_dict_method):
        raw = to_dict_method()
        if isinstance(raw, Mapping):
            return _mapping_to_dict(cast("Mapping[object, object]", raw))
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _serialize(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return str(value)


def _mapping_to_dict(mapping: Mapping[object, object]) -> dict[str, object]:
    """Serialize a mapping with string keys."""
    return {str(key): _serialize(value) for key, value in mapping.items()}


def _location_from_dict(data: Mapping[str, object]) -> str:
    """Return a compact file/function/line location string when fields exist."""
    parts: list[str] = []
    file_name = data.get("filename") or data.get("file")
    if file_name:
        parts.append(str(file_name))
    function_name = data.get("function_name") or data.get("function")
    if function_name:
        parts.append(f"in {function_name}()")
    line_number = data.get("line_number") or data.get("line")
    if line_number:
        parts.append(f"line {line_number}")
    return ", ".join(parts)


def _enum_or_string(value: object) -> str:
    """Return an enum name/value or stable string representation."""
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    return str(value)


__all__ = [
    "ArithmeticIssue",
    "ContractIssue",
    "Issue",
    "IssueKind",
    "Severity",
    "count",
    "data",
    "found",
    "records",
    "render",
]
