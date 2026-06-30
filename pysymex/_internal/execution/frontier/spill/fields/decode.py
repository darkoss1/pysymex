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

"""Decoded JSON field validation for frontier spill materialization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Never, cast

from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import FrontierMaterializationError

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.spill.values.types import JsonValue


def object_payload(raw_payload: object) -> Mapping[str, object] | None:
    """Return a string-keyed mapping from decoded JSON."""
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def required_json_value(payload: Mapping[str, object], key: str) -> JsonValue:
    """Return a required JSON value from a decoded mapping."""
    raw_value = payload.get(key)
    if is_json_value(raw_value):
        return cast("JsonValue", raw_value)
    raise_format_error(payload)
    return None


def required_str(payload: Mapping[str, object], key: str) -> str:
    """Return a required string field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    raise FrontierMaterializationError(
        capsule_id="<unknown>",
        status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
    )


def required_int(payload: Mapping[str, object], key: str) -> int:
    """Return a required integer field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        raise_format_error(payload)
    if isinstance(raw_value, int):
        return raw_value
    raise_format_error(payload)
    return None


def int_sequence(payload: Mapping[str, object], key: str) -> tuple[int, ...]:
    """Return a tuple of integer fields."""
    values: list[int] = []
    for raw_value in required_list(payload, key):
        if isinstance(raw_value, bool) or not isinstance(raw_value, int):
            raise_format_error(payload)
        values.append(raw_value)
    return tuple(values)


def str_sequence(payload: Mapping[str, object], key: str) -> tuple[str, ...]:
    """Return a tuple of string fields."""
    values: list[str] = []
    for raw_value in required_list(payload, key):
        if not isinstance(raw_value, str):
            raise_format_error(payload)
        values.append(raw_value)
    return tuple(values)


def optional_str_tuple(payload: Mapping[str, object], key: str) -> tuple[str, ...] | None:
    """Return an optional string tuple field."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, list):
        raise_format_error(payload)
    values: list[str] = []
    for item in cast("list[object]", raw_value):
        if not isinstance(item, str):
            raise_format_error(payload)
        values.append(item)
    return tuple(values)


def optional_str(payload: Mapping[str, object], key: str) -> str | None:
    """Return an optional string field."""
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, str):
        return raw_value
    raise_format_error(payload)
    return None


def is_json_value(raw_value: object) -> bool:
    """Return whether ``raw_value`` came from JSON with supported structure."""
    if isinstance(raw_value, (bool, int, float, str)) or raw_value is None:
        return True
    if isinstance(raw_value, list):
        return all(is_json_value(item) for item in cast("list[object]", raw_value))
    if isinstance(raw_value, dict):
        raw_mapping = cast("dict[object, object]", raw_value)
        return all(
            isinstance(key, str) and is_json_value(value) for key, value in raw_mapping.items()
        )
    return False


def required_list(payload: Mapping[str, object], key: str) -> list[object]:
    """Return a required JSON list field as objects."""
    raw_value = payload.get(key)
    if not isinstance(raw_value, list):
        raise_format_error(payload)
    return cast("list[object]", raw_value)


def decoded_pair(raw_pair: object, payload: Mapping[str, object]) -> list[object]:
    """Return a decoded JSON pair."""
    if not isinstance(raw_pair, list):
        raise_format_error(payload)
    return cast("list[object]", raw_pair)


def raise_format_error(payload: Mapping[str, object]) -> Never:
    """Raise a typed materialization error for malformed spill files."""
    raise FrontierMaterializationError(
        capsule_id=str(payload.get("capsule_id", "<unknown>")),
        status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
    )
