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

"""Instruction-list encoding for frontier spill payloads."""

from __future__ import annotations

import dis
from collections.abc import Mapping
from typing import cast

from pysymex.execution.frontier.spill.values import JsonObject, JsonValue

__all__ = [
    "SpillInstructionDecodeError",
    "current_instructions_payload",
    "decode_current_instructions",
]

_INSTRUCTION_FIELDS = frozenset(dis.Instruction._fields)


class SpillInstructionDecodeError(ValueError):
    """Raised when spill instruction metadata is malformed."""


def current_instructions_payload(instructions: tuple[object, ...]) -> list[JsonValue] | None:
    """Return JSON-safe current-instruction metadata."""
    encoded: list[JsonValue] = []
    for instruction in instructions:
        payload = _instruction_payload(instruction)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def decode_current_instructions(raw_instructions: object) -> list[object] | None:
    """Decode an optional current-instruction list from a spill payload."""
    if raw_instructions is None:
        return None
    if not isinstance(raw_instructions, list):
        raise SpillInstructionDecodeError("current instructions must be a list")
    return [
        _decode_instruction(raw_instruction)
        for raw_instruction in cast("list[object]", raw_instructions)
    ]


def _instruction_payload(instruction: object) -> JsonObject | None:
    if type(instruction) is not dis.Instruction:
        return None
    argval = _json_value(instruction.argval)
    positions = (
        _positions_payload(instruction.positions) if instruction.positions is not None else None
    )
    if (
        isinstance(argval, _UnsupportedSentinel)
        or (
            _has_instruction_field("label") and _invalid_optional_int(getattr(instruction, "label"))
        )
        or (instruction.positions is not None and positions is None)
        or (_has_instruction_field("cache_info") and getattr(instruction, "cache_info") is not None)
    ):
        return None
    payload: JsonObject = {
        "opname": instruction.opname,
        "opcode": instruction.opcode,
        "arg": instruction.arg,
        "argval": argval,
        "argrepr": instruction.argrepr,
        "offset": instruction.offset,
        "starts_line": instruction.starts_line,
        "positions": positions,
    }
    if _has_instruction_field("is_jump_target"):
        payload["is_jump_target"] = instruction.is_jump_target
    if _has_instruction_field("start_offset"):
        payload["start_offset"] = instruction.start_offset
    if _has_instruction_field("line_number"):
        payload["line_number"] = instruction.line_number
    if _has_instruction_field("label"):
        payload["label"] = instruction.label
    if _has_instruction_field("cache_info"):
        payload["cache_info"] = None
    return payload


def _positions_payload(positions: object) -> JsonObject | None:
    if type(positions) is not dis.Positions:
        return None
    if (
        _invalid_optional_int(positions.lineno)
        or _invalid_optional_int(positions.end_lineno)
        or _invalid_optional_int(positions.col_offset)
        or _invalid_optional_int(positions.end_col_offset)
    ):
        return None
    return {
        "lineno": positions.lineno,
        "end_lineno": positions.end_lineno,
        "col_offset": positions.col_offset,
        "end_col_offset": positions.end_col_offset,
    }


def _decode_instruction(raw_instruction: object) -> dis.Instruction:
    payload = _object_payload(raw_instruction)
    if payload is None:
        raise SpillInstructionDecodeError("instruction metadata is malformed")
    _reject_unexpected_instruction_fields(payload)
    if _has_instruction_field("cache_info") and payload.get("cache_info") is not None:
        raise SpillInstructionDecodeError("instruction cache metadata is unsupported")

    kwargs: dict[str, object] = {
        "opname": _required_str(payload, "opname"),
        "opcode": _required_int(payload, "opcode"),
        "arg": _optional_int(payload, "arg"),
        "argval": _required_json_value(payload, "argval"),
        "argrepr": _required_str(payload, "argrepr"),
        "offset": _required_int(payload, "offset"),
        "starts_line": _optional_start_line(payload, "starts_line"),
        "positions": _decode_positions(payload.get("positions")),
    }
    if _has_instruction_field("is_jump_target"):
        kwargs["is_jump_target"] = _required_bool(payload, "is_jump_target")
    if _has_instruction_field("start_offset"):
        kwargs["start_offset"] = _required_int(payload, "start_offset")
    if _has_instruction_field("line_number"):
        kwargs["line_number"] = _optional_int(payload, "line_number")
    if _has_instruction_field("label"):
        kwargs["label"] = _optional_int(payload, "label")
    if _has_instruction_field("cache_info"):
        kwargs["cache_info"] = None

    return _instruction_from_kwargs(kwargs)


def _instruction_from_kwargs(kwargs: Mapping[str, object]) -> dis.Instruction:
    """Construct a CPython instruction across version-specific namedtuple fields."""
    field_values = tuple(kwargs[field] for field in dis.Instruction._fields)
    return dis.Instruction._make(field_values)


def _decode_positions(raw_positions: object) -> dis.Positions | None:
    if raw_positions is None:
        return None
    payload = _object_payload(raw_positions)
    if payload is None:
        raise SpillInstructionDecodeError("instruction positions are malformed")
    return dis.Positions(
        lineno=_optional_int(payload, "lineno"),
        end_lineno=_optional_int(payload, "end_lineno"),
        col_offset=_optional_int(payload, "col_offset"),
        end_col_offset=_optional_int(payload, "end_col_offset"),
    )


def _object_payload(raw_payload: object) -> Mapping[str, object] | None:
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def _required_str(payload: Mapping[str, object], key: str) -> str:
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be a string")


def _required_int(payload: Mapping[str, object], key: str) -> int:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        raise SpillInstructionDecodeError(f"instruction field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be an integer")


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be a boolean")


def _optional_int(payload: Mapping[str, object], key: str) -> int | None:
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise SpillInstructionDecodeError(f"instruction field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be an integer or null")


def _optional_start_line(payload: Mapping[str, object], key: str) -> int | bool | None:
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return raw_value
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be an integer or null")


def _required_json_value(payload: Mapping[str, object], key: str) -> JsonValue:
    raw_value = payload.get(key)
    if _is_json_value(raw_value):
        return cast("JsonValue", raw_value)
    raise SpillInstructionDecodeError(f"instruction field {key!r} must be JSON-safe")


def _json_value(value: object) -> JsonValue | "_UnsupportedSentinel":
    if _is_json_value(value):
        return cast("JsonValue", value)
    return _UNSUPPORTED


def _is_json_value(value: object) -> bool:
    if isinstance(value, (bool, int, float, str)) or value is None:
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in cast("list[object]", value))
    if isinstance(value, dict):
        raw_mapping = cast("dict[object, object]", value)
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in raw_mapping.items()
        )
    return False


def _invalid_optional_int(value: object) -> bool:
    return isinstance(value, bool) or (value is not None and not isinstance(value, int))


def _has_instruction_field(name: str) -> bool:
    return name in _INSTRUCTION_FIELDS


def _reject_unexpected_instruction_fields(payload: Mapping[str, object]) -> None:
    unexpected = set(payload) - _INSTRUCTION_FIELDS
    if unexpected:
        fields = ", ".join(sorted(unexpected))
        raise SpillInstructionDecodeError(f"instruction fields are unsupported: {fields}")


class _UnsupportedSentinel:
    """Sentinel for instruction metadata that cannot cross the spill boundary."""


_UNSUPPORTED = _UnsupportedSentinel()
