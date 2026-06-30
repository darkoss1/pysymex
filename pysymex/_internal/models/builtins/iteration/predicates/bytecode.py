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

"""Bytecode helper predicates for exact iterator predicate recognition."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis


def is_load_arg(instruction: dis.Instruction) -> bool:
    return instruction.opname == "LOAD_FAST" and instruction.arg == 0


def is_load_global(instruction: dis.Instruction, value: object) -> bool:
    return instruction.opname == "LOAD_GLOBAL" and instruction.argval == getattr(
        value,
        "__name__",
        value,
    )


def unary_filter_operator(instruction: dis.Instruction) -> str | None:
    if instruction.opname == "UNARY_NEGATIVE":
        return "negative"
    if instruction.opname == "UNARY_POSITIVE":
        return "positive"
    if instruction.opname == "UNARY_INVERT":
        return "invert"
    if (
        instruction.opname == "CALL_INTRINSIC_1"
        and instruction.argrepr == "INTRINSIC_UNARY_POSITIVE"
    ):
        return "positive"
    return None


def is_not_filter_predicate(instructions: list[dis.Instruction]) -> bool:
    if len(instructions) == 3:
        load_arg, unary_not, ret = instructions
        return (
            is_load_arg(load_arg)
            and unary_not.opname == "UNARY_NOT"
            and ret.opname == "RETURN_VALUE"
        )
    if len(instructions) == 4:
        load_arg, to_bool, unary_not, ret = instructions
        return (
            is_load_arg(load_arg)
            and to_bool.opname == "TO_BOOL"
            and unary_not.opname == "UNARY_NOT"
            and ret.opname == "RETURN_VALUE"
        )
    return False
