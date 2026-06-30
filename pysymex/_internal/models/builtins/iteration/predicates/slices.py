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

"""Literal slice operand recognition for modeled iterator predicates."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import dis

INVALID_SLICE_BOUND = object()


def literal_slice_operand(
    instructions: list[dis.Instruction],
) -> slice[int | None, int | None, int | None] | None:
    if len(instructions) == 3 and instructions[2].opname == "BINARY_SLICE":
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        if start is INVALID_SLICE_BOUND or stop is INVALID_SLICE_BOUND:
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop))

    if len(instructions) == 4 and instructions[2].opname == "BUILD_SLICE":
        if instructions[3].opname != "BINARY_SUBSCR":
            return None
        arg_count = instructions[2].arg
        if arg_count != 2:
            return None
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        if start is INVALID_SLICE_BOUND or stop is INVALID_SLICE_BOUND:
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop))

    if len(instructions) == 5 and instructions[3].opname == "BUILD_SLICE":
        if instructions[4].opname != "BINARY_SUBSCR":
            return None
        arg_count = instructions[3].arg
        if arg_count != 3:
            return None
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        step = _literal_slice_bound(instructions[2])
        if (
            start is INVALID_SLICE_BOUND
            or stop is INVALID_SLICE_BOUND
            or step is INVALID_SLICE_BOUND
            or step == 0
        ):
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop, step))

    return None


def _literal_slice_bound(instruction: dis.Instruction) -> int | None | object:
    if instruction.opname != "LOAD_CONST":
        return INVALID_SLICE_BOUND
    value = instruction.argval
    if value is None or isinstance(value, int):
        return value
    return INVALID_SLICE_BOUND
