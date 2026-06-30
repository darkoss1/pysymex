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

"""Callee bytecode and exception-table loading for interprocedural entry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.exceptions import get_exception_entries
from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    import dis
    import types


@dataclass(frozen=True, slots=True)
class CalleeBytecode:
    """Instruction stream and exception metadata for a callee code object."""

    instructions: list[dis.Instruction]
    exception_entries: list[object]


def load_callee_bytecode(func_code: types.CodeType) -> CalleeBytecode | None:
    """Load callee instructions and exception entries, or return ``None`` if unavailable."""
    try:
        instructions = list(get_instructions(func_code))
    except (TypeError, ValueError):
        return None
    return CalleeBytecode(
        instructions=instructions,
        exception_entries=list(get_exception_entries(func_code)),
    )
