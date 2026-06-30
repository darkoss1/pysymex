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

"""Strict scalar and enum field decoders for detector spill payloads."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, TypeVar, cast

from pysymex._internal.analysis.detectors.detector.types import Severity
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.frontier.spill.detector.types import SpillDetectorDecodeError
from pysymex._internal.execution.frontier.spill.fields.decode import is_json_value

if TYPE_CHECKING:
    from collections.abc import Mapping

EnumT = TypeVar("EnumT", bound=Enum)


def issue_kind(payload: Mapping[str, object], key: str) -> IssueKind:
    """Decode an ``IssueKind`` enum member field."""
    return enum_member(IssueKind, required_str(payload, key))


def optional_severity(payload: Mapping[str, object], key: str) -> Severity | None:
    """Decode an optional ``Severity`` enum member field."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        msg = "detector issue severity is malformed"
        raise SpillDetectorDecodeError(msg)
    return enum_member(Severity, raw_value)


def enum_member(enum_type: type[EnumT], name: str) -> EnumT:
    """Return one enum member by name, failing closed for unsupported values."""
    try:
        return enum_type[name]
    except KeyError as exc:
        msg = "detector enum value is unsupported"
        raise SpillDetectorDecodeError(msg) from exc


def required_str(payload: Mapping[str, object], key: str) -> str:
    """Decode a required string field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    msg = f"detector issue field {key!r} must be a string"
    raise SpillDetectorDecodeError(msg)


def optional_str(payload: Mapping[str, object], key: str) -> str | None:
    """Decode an optional string field."""
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, str):
        return raw_value
    msg = f"detector issue field {key!r} must be a string or null"
    raise SpillDetectorDecodeError(msg)


def required_int(payload: Mapping[str, object], key: str) -> int:
    """Decode a required integer field, rejecting ``bool`` masquerading as ``int``."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        msg = f"detector issue field {key!r} must be an integer"
        raise SpillDetectorDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"detector issue field {key!r} must be an integer"
    raise SpillDetectorDecodeError(msg)


def optional_int(payload: Mapping[str, object], key: str) -> int | None:
    """Decode an optional integer field, rejecting ``bool`` masquerading as ``int``."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        msg = f"detector issue field {key!r} must be an integer"
        raise SpillDetectorDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"detector issue field {key!r} must be an integer or null"
    raise SpillDetectorDecodeError(msg)


def required_bool(payload: Mapping[str, object], key: str) -> bool:
    """Decode a required boolean field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    msg = f"detector issue field {key!r} must be a bool"
    raise SpillDetectorDecodeError(msg)


def required_float(payload: Mapping[str, object], key: str) -> float:
    """Decode a required numeric field, rejecting ``bool`` masquerading as a number."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        msg = f"detector issue field {key!r} must be a number"
        raise SpillDetectorDecodeError(msg)
    if isinstance(raw_value, (int, float)):
        return float(raw_value)
    msg = f"detector issue field {key!r} must be a number"
    raise SpillDetectorDecodeError(msg)


def str_tuple(payload: Mapping[str, object], key: str) -> tuple[str, ...]:
    """Decode a required list of strings as an immutable tuple."""
    raw_value = payload.get(key)
    if not isinstance(raw_value, list):
        msg = f"detector issue field {key!r} must be a list"
        raise SpillDetectorDecodeError(msg)
    values: list[str] = []
    for item in cast("list[object]", raw_value):
        if not isinstance(item, str):
            msg = f"detector issue field {key!r} must contain strings"
            raise SpillDetectorDecodeError(msg)
        values.append(item)
    return tuple(values)


def optional_counterexample(
    payload: Mapping[str, object],
    key: str,
) -> dict[str, object] | None:
    """Decode an optional JSON-safe counterexample object."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, dict):
        msg = "detector issue counterexample is malformed"
        raise SpillDetectorDecodeError(msg)
    raw_mapping = cast("dict[object, object]", raw_value)
    if not is_json_value(raw_mapping):
        msg = "detector issue counterexample is malformed"
        raise SpillDetectorDecodeError(msg)
    return {cast("str", item_key): item_value for item_key, item_value in raw_mapping.items()}
