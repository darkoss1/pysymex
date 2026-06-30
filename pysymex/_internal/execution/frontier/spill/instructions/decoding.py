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

"""Decode CPython instruction metadata from frontier spill payloads."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .fields import (
    has_instruction_field,
    optional_int,
    optional_start_line,
    reject_unexpected_instruction_fields,
    required_bool,
    required_int,
    required_json_value,
    required_str,
)
from .types import SpillInstructionDecodeError

if TYPE_CHECKING:
    from collections.abc import Mapping


def decode_current_instructions(raw_instructions: object) -> list[object] | None:
    """Decode an optional current-instruction list from a spill payload."""
    if raw_instructions is None:
        return None
    if not isinstance(raw_instructions, list):
        msg = "current instructions must be a list"
        raise SpillInstructionDecodeError(msg)
    return [
        _decode_instruction(raw_instruction)
        for raw_instruction in cast("list[object]", raw_instructions)
    ]


def _decode_instruction(raw_instruction: object) -> dis.Instruction:
    payload = object_payload(raw_instruction)
    if payload is None:
        msg = "instruction metadata is malformed"
        raise SpillInstructionDecodeError(msg)
    reject_unexpected_instruction_fields(payload)
    if has_instruction_field("cache_info") and payload.get("cache_info") is not None:
        msg = "instruction cache metadata is unsupported"
        raise SpillInstructionDecodeError(msg)

    kwargs: dict[str, object] = {
        "opname": required_str(payload, "opname"),
        "opcode": required_int(payload, "opcode"),
        "arg": optional_int(payload, "arg"),
        "argval": required_json_value(payload, "argval"),
        "argrepr": required_str(payload, "argrepr"),
        "offset": required_int(payload, "offset"),
        "starts_line": optional_start_line(payload, "starts_line"),
        "positions": _decode_positions(payload.get("positions")),
    }
    if has_instruction_field("is_jump_target"):
        kwargs["is_jump_target"] = required_bool(payload, "is_jump_target")
    if has_instruction_field("start_offset"):
        kwargs["start_offset"] = required_int(payload, "start_offset")
    if has_instruction_field("line_number"):
        kwargs["line_number"] = optional_int(payload, "line_number")
    if has_instruction_field("label"):
        kwargs["label"] = optional_int(payload, "label")
    if has_instruction_field("cache_info"):
        kwargs["cache_info"] = None

    return _instruction_from_kwargs(kwargs)


def _instruction_from_kwargs(kwargs: Mapping[str, object]) -> dis.Instruction:
    """Construct a CPython instruction across version-specific namedtuple fields."""
    field_values = tuple(kwargs[field] for field in dis.Instruction._fields)
    return dis.Instruction._make(field_values)


def _decode_positions(raw_positions: object) -> dis.Positions | None:
    if raw_positions is None:
        return None
    payload = object_payload(raw_positions)
    if payload is None:
        msg = "instruction positions are malformed"
        raise SpillInstructionDecodeError(msg)
    return dis.Positions(
        lineno=optional_int(payload, "lineno"),
        end_lineno=optional_int(payload, "end_lineno"),
        col_offset=optional_int(payload, "col_offset"),
        end_col_offset=optional_int(payload, "end_col_offset"),
    )
