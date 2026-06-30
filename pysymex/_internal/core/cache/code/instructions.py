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

"""Instruction tuple cache and CPython metadata normalization."""

from __future__ import annotations

import dis
import functools
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.cache.code.wrappers import ProcessCodeCache
from pysymex._internal.core.cache.control import register_process_cache_clearer

if TYPE_CHECKING:
    import types


@functools.lru_cache(maxsize=2048)
def _cached_get_instructions(code: types.CodeType) -> tuple[dis.Instruction, ...]:
    """Return a cached immutable instruction tuple for ``code``."""
    return _uncached_get_instructions(code)


def _uncached_get_instructions(code: types.CodeType) -> tuple[dis.Instruction, ...]:
    """Return immutable instructions without consulting the process LRU."""
    return tuple(
        _normalize_instruction(code, instruction) for instruction in dis.get_instructions(code)
    )


def _normalize_instruction(
    code: types.CodeType,
    instruction: dis.Instruction,
) -> dis.Instruction:
    """Patch CPython-version metadata gaps in disassembled instructions."""
    if instruction.opname != "KW_NAMES" or not isinstance(instruction.arg, int):
        return instruction
    try:
        kw_names = code.co_consts[instruction.arg]
    except IndexError:
        return instruction
    if not isinstance(kw_names, tuple):
        return instruction
    kw_names_tuple = cast("tuple[object, ...]", kw_names)
    return instruction._replace(argval=kw_names_tuple, argrepr=repr(kw_names_tuple))


get_instructions = ProcessCodeCache(_cached_get_instructions, _uncached_get_instructions)
"""Return immutable instructions for ``code``.

Entries normally use a process-wide LRU cache keyed by the code object. While
``pysymex._internal.core.cache.control.process_caches_disabled`` is active, calls bypass
that LRU and do not store entries.
"""


register_process_cache_clearer("core.code.instructions", get_instructions.cache_clear)
