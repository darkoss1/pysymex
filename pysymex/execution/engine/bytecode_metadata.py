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

"""Bytecode metadata preparation and immutable execution-prep caches."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import dis
import functools
from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.core.cache import get_exception_entries, get_instructions
from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.session.state import ExecutionSession

__all__ = [
    "build_line_mapping",
    "clear_line_mapping_cache",
    "line_mapping_cache_stats",
    "prepare_bytecode_execution",
]

LineMappingEntries = tuple[tuple[int, int], ...]
ExceptionEntries = tuple[object, ...]


def prepare_bytecode_execution(
    *,
    session: ExecutionSession,
    dispatcher: OpcodeDispatcher,
    code: CodeType,
    bytecode_source: Callable[..., object] | CodeType,
) -> None:
    """Install bytecode, exception, and line metadata for the active run."""
    session.instructions = list(get_instructions(code))
    dispatcher.set_instructions(session.instructions)
    entries = (
        get_exception_entries(code)
        if _bytecode_source_matches_code(bytecode_source, code)
        else _exception_entries_from_source(bytecode_source)
    )
    dispatcher.set_exception_entries(list(entries))
    build_line_mapping(session=session, code=code)


def build_line_mapping(*, session: ExecutionSession, code: CodeType) -> None:
    """Populate per-PC source-line metadata from the active instruction stream."""
    if is_process_cache_disabled():
        _install_line_mapping(session, _line_mapping_from_instructions(session.instructions))
        return

    cached_instructions = get_instructions(code)
    if _active_stream_matches_code(session.instructions, cached_instructions):
        _install_line_mapping(session, _line_mapping_for_code(code))
        return
    _install_line_mapping(session, _line_mapping_from_instructions(session.instructions))


def clear_line_mapping_cache() -> None:
    """Clear cached bytecode PC-to-line metadata."""
    _line_mapping_for_code.cache_clear()


register_process_cache_clearer("execution.line_mapping_cache", clear_line_mapping_cache)


def line_mapping_cache_stats() -> dict[str, int]:
    """Return line-mapping cache hit, miss, and size counters."""
    cache_info = _line_mapping_for_code.cache_info()
    max_size = cache_info.maxsize if isinstance(cache_info.maxsize, int) else 0
    return {
        "hits": cache_info.hits,
        "misses": cache_info.misses,
        "maxsize": max_size,
        "currsize": cache_info.currsize,
    }


def _bytecode_source_matches_code(
    bytecode_source: Callable[..., object] | CodeType,
    code: CodeType,
) -> bool:
    """Return true when a bytecode source is represented by ``code``."""
    if bytecode_source is code:
        return True
    return getattr(bytecode_source, "__code__", None) is code


def _exception_entries_from_source(
    bytecode_source: Callable[..., object] | CodeType,
) -> ExceptionEntries:
    """Return exception entries for a non-standard bytecode source."""
    try:
        bytecode_obj = dis.Bytecode(bytecode_source)
        entries = getattr(bytecode_obj, "exception_entries", ())
        return tuple(entries)
    except (AttributeError, TypeError):
        return ()


@functools.lru_cache(maxsize=2048)
def _line_mapping_for_code(code: CodeType) -> LineMappingEntries:
    """Return cached per-PC line metadata for an immutable code object."""
    return _line_mapping_from_instructions(get_instructions(code))


def _active_stream_matches_code(
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


def _line_mapping_from_instructions(
    instructions: Iterable[dis.Instruction],
) -> LineMappingEntries:
    """Build immutable line-mapping entries from an instruction stream."""
    pc_to_line: dict[int, int] = {}
    last_line = None
    for index, instr in enumerate(instructions):
        if hasattr(instr, "positions") and instr.positions:
            line = instr.positions.lineno
            if line:
                pc_to_line[index] = line
                last_line = line
            elif last_line:
                pc_to_line[index] = last_line
        elif (line := get_starts_line(instr)) is not None:
            pc_to_line[index] = line
            last_line = line
        elif last_line:
            pc_to_line[index] = last_line
    return tuple(pc_to_line.items())


def _install_line_mapping(session: ExecutionSession, entries: LineMappingEntries) -> None:
    """Replace session line metadata while preserving the mapping object."""
    session.pc_to_line.clear()
    session.pc_to_line.update(entries)
