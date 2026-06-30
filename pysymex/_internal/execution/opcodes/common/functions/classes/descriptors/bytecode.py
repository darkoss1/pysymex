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

"""Class-body bytecode scanning helpers for descriptor registration."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    import dis

CLASS_BODY_DECORATOR_NOOPS = frozenset(("CACHE", "PRECALL"))


def class_body_effective_instructions(class_body: types.CodeType) -> list[dis.Instruction]:
    """Return class-body bytecode with decorator no-op opcodes removed."""
    return [
        instr
        for instr in get_instructions(class_body)
        if instr.opname not in CLASS_BODY_DECORATOR_NOOPS
    ]


def last_make_function_before(
    instructions: list[dis.Instruction],
    store_index: int,
) -> int | None:
    """Find the ``MAKE_FUNCTION`` index preceding a class-body ``STORE_*``."""
    if store_index < 1 or instructions[store_index - 1].opname != "CALL":
        return None
    for index in range(store_index - 2, -1, -1):
        instr = instructions[index]
        if instr.opname == "MAKE_FUNCTION":
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def code_const_before_make_function(
    instructions: list[dis.Instruction],
    make_index: int,
) -> int | None:
    """Locate the ``LOAD_CONST`` code object feeding a ``MAKE_FUNCTION``."""
    for index in range(make_index - 1, -1, -1):
        instr = instructions[index]
        if instr.opname == "LOAD_CONST" and isinstance(instr.argval, types.CodeType):
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def previous_class_body_store_index(
    instructions: list[dis.Instruction],
    before_index: int,
) -> int:
    """Return the index of the previous ``STORE_NAME``/``STORE_GLOBAL`` in a body."""
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname in {"STORE_NAME", "STORE_GLOBAL"}:
            return index
    return -1
