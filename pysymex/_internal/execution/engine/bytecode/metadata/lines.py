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

"""Source-line metadata mapping and cache management for execution sessions."""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from pysymex._internal.core.bytecode import get_position_line, get_starts_line
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)

if TYPE_CHECKING:
    import dis
    from collections.abc import Iterable
    from types import CodeType

    from pysymex._internal.execution.session.state.core import ExecutionSession

LineMappingEntries = tuple[tuple[int, int], ...]


def build_line_mapping(*, session: ExecutionSession, code: CodeType) -> None:
    """Populate per-PC source-line metadata from the active instruction stream."""
    if is_process_cache_disabled():
        install_line_mapping(session, line_mapping_from_instructions(session.instructions))
        return

    cached_instructions = get_instructions(code)
    if active_stream_matches_code(session.instructions, cached_instructions):
        install_line_mapping(session, line_mapping_for_code(code))
        return
    install_line_mapping(session, line_mapping_from_instructions(session.instructions))


def clear_line_mapping_cache() -> None:
    """Clear cached bytecode PC-to-line metadata."""
    line_mapping_for_code.cache_clear()


register_process_cache_clearer("execution.line_mapping_cache", clear_line_mapping_cache)


def line_mapping_cache_stats() -> dict[str, int]:
    """Return line-mapping cache hit, miss, and size counters."""
    cache_info = line_mapping_for_code.cache_info()
    max_size = cache_info.maxsize if isinstance(cache_info.maxsize, int) else 0
    return {
        "hits": cache_info.hits,
        "misses": cache_info.misses,
        "maxsize": max_size,
        "currsize": cache_info.currsize,
    }


@functools.lru_cache(maxsize=2048)
def line_mapping_for_code(code: CodeType) -> LineMappingEntries:
    """Return cached per-PC line metadata for an immutable code object."""
    return line_mapping_from_instructions(get_instructions(code))


def active_stream_matches_code(
    active_instructions: list[dis.Instruction],
    cached_instructions: tuple[dis.Instruction, ...],
) -> bool:
    """Return true when the active stream is the normal copy of cached bytecode."""
    if len(active_instructions) != len(cached_instructions):
        return False
    if not active_instructions:
        return True
    return (
        active_instructions[0] is cached_instructions[0]
        and active_instructions[-1] is cached_instructions[-1]
    )


def line_mapping_from_instructions(
    instructions: Iterable[dis.Instruction],
) -> LineMappingEntries:
    """Build immutable line-mapping entries from an instruction stream."""
    pc_to_line: dict[int, int] = {}
    last_line = None
    for index, instr in enumerate(instructions):
        if (line := get_position_line(instr)) is not None or (
            line := get_starts_line(instr)
        ) is not None:
            pc_to_line[index] = line
            last_line = line
        elif last_line:
            pc_to_line[index] = last_line
    return tuple(pc_to_line.items())


def install_line_mapping(session: ExecutionSession, entries: LineMappingEntries) -> None:
    """Replace session line metadata while preserving the mapping object."""
    session.pc_to_line.clear()
    session.pc_to_line.update(entries)
