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

"""Exception-table stream indexing for opcode dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.bytecode import instruction_stream_key

if TYPE_CHECKING:
    import dis


def offset_index_by_instruction_stream(instructions: list[dis.Instruction]) -> dict[int, int]:
    """Return bytecode-offset to instruction-index metadata for one stream."""
    return {instr.offset: idx for idx, instr in enumerate(instructions)}


def select_entries_for_stream(
    instructions: list[dis.Instruction],
    pending_entries: list[object],
    entries_by_stream: dict[tuple[int, ...], list[object]],
    *,
    previous_stream_was_empty: bool,
) -> list[object]:
    """Return exception entries that belong to the selected instruction stream."""
    stream_key = instruction_stream_key(instructions)
    registered_entries = entries_by_stream.get(stream_key)
    if registered_entries is not None:
        return list(registered_entries)
    if previous_stream_was_empty and pending_entries:
        entries = list(pending_entries)
        entries_by_stream[stream_key] = list(entries)
        return entries
    return []


def store_exception_entries_for_stream(
    instructions: list[dis.Instruction],
    entries: list[object],
    entries_by_stream: dict[tuple[int, ...], list[object]],
) -> list[object]:
    """Register exception entries for an instruction stream and return an owned copy."""
    stored_entries = list(entries)
    entries_by_stream[instruction_stream_key(instructions)] = list(stored_entries)
    return stored_entries


def handler_index_for_offset(
    offset: int,
    entries: list[object],
    offset_to_index: dict[int, int],
    handler_by_offset: dict[int, int | None],
) -> int | None:
    """Return the most nested exception handler index covering ``offset``."""
    if offset in handler_by_offset:
        return handler_by_offset[offset]

    best_idx: int | None = None
    best_start: int | None = None
    best_end: int | None = None
    for entry in entries:
        start = cast("int | None", getattr(entry, "start", None))
        end = cast("int | None", getattr(entry, "end", None))
        target = cast("int | None", getattr(entry, "target", None))
        if start is None or end is None or target is None:
            continue
        if not (start <= offset < end):
            continue
        idx = offset_to_index.get(target)
        if idx is None:
            continue
        if best_start is None:
            best_idx = idx
            best_start = start
            best_end = end
            continue
        if start > best_start:
            best_idx = idx
            best_start = start
            best_end = end
            continue
        if start == best_start and best_end is not None and end < best_end:
            best_idx = idx
            best_end = end

    handler_by_offset[offset] = best_idx
    return best_idx
