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

"""Instruction-stream and exception metadata transitions for opcode dispatch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.exception.index import (
    offset_index_by_instruction_stream,
    select_entries_for_stream,
    store_exception_entries_for_stream,
)

if TYPE_CHECKING:
    import dis


@dataclass(frozen=True)
class InstructionStreamSelection:
    """Selected instruction stream, offset index, and matching exception entries."""

    instructions: list[dis.Instruction]
    offset_to_index: dict[int, int]
    exception_entries: list[object]


def select_instruction_stream(
    instructions: list[dis.Instruction],
    current_instructions: list[dis.Instruction],
    exception_entries: list[object],
    entries_by_stream: dict[tuple[int, ...], list[object]],
) -> InstructionStreamSelection | None:
    """Select active stream metadata, returning ``None`` if the stream object is unchanged."""
    if instructions is current_instructions:
        return None
    previous_stream_was_empty = not current_instructions
    pending_entries = list(exception_entries)
    return InstructionStreamSelection(
        instructions=instructions,
        offset_to_index=offset_index_by_instruction_stream(instructions),
        exception_entries=select_entries_for_stream(
            instructions,
            pending_entries,
            entries_by_stream,
            previous_stream_was_empty=previous_stream_was_empty,
        ),
    )


def store_active_exception_entries(
    instructions: list[dis.Instruction],
    entries: list[object],
    entries_by_stream: dict[tuple[int, ...], list[object]],
) -> list[object]:
    """Store exception entries for the active stream and return an owned copy."""
    return store_exception_entries_for_stream(instructions, entries, entries_by_stream)


def register_stream_exception_entries(
    instructions: list[dis.Instruction],
    entries: list[object],
    entries_by_stream: dict[tuple[int, ...], list[object]],
) -> None:
    """Register exception entries for an inactive stream."""
    store_exception_entries_for_stream(instructions, entries, entries_by_stream)
