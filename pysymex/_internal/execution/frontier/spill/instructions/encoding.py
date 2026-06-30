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

"""Encode CPython instruction metadata for frontier spill payloads."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from .fields import has_instruction_field, invalid_optional_int, json_value
from .types import UnsupportedInstructionSentinel

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue


def current_instructions_payload(instructions: tuple[object, ...]) -> list[JsonValue] | None:
    """Return JSON-safe current-instruction metadata."""
    encoded: list[JsonValue] = []
    for instruction in instructions:
        payload = _instruction_payload(instruction)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def _instruction_payload(instruction: object) -> JsonObject | None:
    if type(instruction) is not dis.Instruction:
        return None
    argval = json_value(instruction.argval)
    label = getattr(instruction, "label", None) if has_instruction_field("label") else None
    cache_info = (
        getattr(instruction, "cache_info", None) if has_instruction_field("cache_info") else None
    )
    positions = (
        _positions_payload(instruction.positions) if instruction.positions is not None else None
    )
    if (
        isinstance(argval, UnsupportedInstructionSentinel)
        or (has_instruction_field("label") and invalid_optional_int(label))
        or (instruction.positions is not None and positions is None)
        or (has_instruction_field("cache_info") and cache_info is not None)
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
    if has_instruction_field("is_jump_target"):
        payload["is_jump_target"] = instruction.is_jump_target
    if has_instruction_field("start_offset"):
        start_offset = getattr(instruction, "start_offset", None)
        if invalid_optional_int(start_offset):
            return None
        payload["start_offset"] = cast("int | None", start_offset)
    if has_instruction_field("line_number"):
        line_number = getattr(instruction, "line_number", None)
        if invalid_optional_int(line_number):
            return None
        payload["line_number"] = cast("int | None", line_number)
    if has_instruction_field("label"):
        payload["label"] = cast("int | None", label)
    if has_instruction_field("cache_info"):
        payload["cache_info"] = None
    return payload


def _positions_payload(positions: object) -> JsonObject | None:
    if type(positions) is not dis.Positions:
        return None
    if (
        invalid_optional_int(positions.lineno)
        or invalid_optional_int(positions.end_lineno)
        or invalid_optional_int(positions.col_offset)
        or invalid_optional_int(positions.end_col_offset)
    ):
        return None
    return {
        "lineno": positions.lineno,
        "end_lineno": positions.end_lineno,
        "col_offset": positions.col_offset,
        "end_col_offset": positions.end_col_offset,
    }
