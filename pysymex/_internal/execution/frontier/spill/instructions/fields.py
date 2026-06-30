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

"""Scalar field helpers for spill instruction metadata."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.frontier.spill.fields.decode import is_json_value

from .types import (
    INSTRUCTION_FIELDS,
    UNSUPPORTED_INSTRUCTION_METADATA,
    SpillInstructionDecodeError,
    UnsupportedInstructionSentinel,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.execution.frontier.spill.values.types import JsonValue


def required_str(payload: Mapping[str, object], key: str) -> str:
    """Return a required string instruction field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    msg = f"instruction field {key!r} must be a string"
    raise SpillInstructionDecodeError(msg)


def required_int(payload: Mapping[str, object], key: str) -> int:
    """Return a required integer instruction field, excluding ``bool``."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        msg = f"instruction field {key!r} must be an integer"
        raise SpillInstructionDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"instruction field {key!r} must be an integer"
    raise SpillInstructionDecodeError(msg)


def required_bool(payload: Mapping[str, object], key: str) -> bool:
    """Return a required boolean instruction field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    msg = f"instruction field {key!r} must be a boolean"
    raise SpillInstructionDecodeError(msg)


def optional_int(payload: Mapping[str, object], key: str) -> int | None:
    """Return an optional integer instruction field, excluding ``bool``."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        msg = f"instruction field {key!r} must be an integer"
        raise SpillInstructionDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"instruction field {key!r} must be an integer or null"
    raise SpillInstructionDecodeError(msg)


def optional_start_line(payload: Mapping[str, object], key: str) -> int | bool | None:
    """Return a CPython-compatible optional ``starts_line`` field."""
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return raw_value
    msg = f"instruction field {key!r} must be an integer or null"
    raise SpillInstructionDecodeError(msg)


def required_json_value(payload: Mapping[str, object], key: str) -> JsonValue:
    """Return a required JSON-safe instruction field."""
    raw_value = payload.get(key)
    if is_json_value(raw_value):
        return cast("JsonValue", raw_value)
    msg = f"instruction field {key!r} must be JSON-safe"
    raise SpillInstructionDecodeError(msg)


def json_value(value: object) -> JsonValue | UnsupportedInstructionSentinel:
    """Return a JSON-safe value or the unsupported sentinel."""
    if is_json_value(value):
        return cast("JsonValue", value)
    return UNSUPPORTED_INSTRUCTION_METADATA


def invalid_optional_int(value: object) -> bool:
    """Return whether an optional integer field is malformed."""
    return isinstance(value, bool) or (value is not None and not isinstance(value, int))


def has_instruction_field(name: str) -> bool:
    """Return whether the running Python version exposes an instruction field."""
    return name in INSTRUCTION_FIELDS


def reject_unexpected_instruction_fields(payload: Mapping[str, object]) -> None:
    """Reject spill payload fields unsupported by this Python version."""
    unexpected = set(payload) - INSTRUCTION_FIELDS
    if unexpected:
        fields = ", ".join(sorted(unexpected))
        msg = f"instruction fields are unsupported: {fields}"
        raise SpillInstructionDecodeError(msg)
