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

"""Instruction extraction helpers for non-executing mapping-pattern recognition."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    import dis

_IGNORED_PATTERN_OPS = frozenset(
    ("CACHE", "COPY_FREE_VARS", "EXTENDED_ARG", "NOP", "PRECALL", "RESUME"),
)


def method_code(method: object) -> types.CodeType | None:
    """Return the code object for a modeled method."""
    func = getattr(method, "func", None)
    return func if isinstance(func, types.CodeType) else None


def effective_instructions(code: types.CodeType | None) -> list[dis.Instruction]:
    """Return bytecode instructions relevant to simple wrapper-pattern matching."""
    if code is None:
        return []
    return [instr for instr in get_instructions(code) if instr.opname not in _IGNORED_PATTERN_OPS]


def loads_local(instr: dis.Instruction, code: types.CodeType, local_index: int) -> bool:
    """Return whether *instr* loads ``code.co_varnames[local_index]``."""
    if local_index >= len(code.co_varnames):
        return False
    return (
        instr.opname in {"LOAD_FAST", "LOAD_FAST_BORROW"}
        and instr.argval == code.co_varnames[local_index]
    )
