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

"""Class slot extraction helpers for common function opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    import types


def extract_literal_slots(class_body: types.CodeType) -> tuple[str, ...] | None:
    """Return literal ``__slots__`` names when the class body stores a constant tuple."""
    instructions = list(get_instructions(class_body))
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or instr.argval != "__slots__":
            continue
        if index < 1:
            return None
        value_instr = instructions[index - 1]
        if value_instr.opname != "LOAD_CONST":
            return None
        value = value_instr.argval
        if isinstance(value, str):
            slots = (value,)
        elif isinstance(value, tuple):
            tuple_items = cast("tuple[object, ...]", value)
            if not all(isinstance(item, str) for item in tuple_items):
                return None
            slots = tuple(str(item) for item in tuple_items)
        else:
            return None
        if "__dict__" in slots:
            return None
        return slots
    return None
