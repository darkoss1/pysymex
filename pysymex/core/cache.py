# pysymex: Python Symbolic Execution & Formal Verification
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

"""Shared instruction cache for ``dis.get_instructions``.

Calling ``dis.get_instructions()`` on the same code object repeatedly is a
surprisingly expensive operation (~14 µs per call on CPython 3.13) because it
walks the bytecode and builds ``Instruction`` namedtuples from scratch every
time.

During a symbolic-execution run, the same code object may be disassembled by
the executor, the loop detector, the state merger, the abstract interpreter,
the CFG builder, and cross-function analysis — easily 6+ times per function.

This module provides a single process-wide cache backed by
``functools.lru_cache`` keyed on the *code object itself*.  ``lru_cache``
gives true LRU eviction in O(1) and is thread-safe under CPython.
"""

from __future__ import annotations

import dis
import functools
import types


@functools.lru_cache(maxsize=2048)
def get_instructions(code: types.CodeType) -> tuple[dis.Instruction, ...]:
    """Return a **cached** tuple of instructions for *code*.

    The returned tuple is immutable — safe to share across callers.
    """
    return tuple(dis.get_instructions(code))


def clear_cache() -> None:
    """Clear the instruction cache.  Call between analysis units if needed."""
    get_instructions.cache_clear()
