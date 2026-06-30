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

"""Extract bounded descriptor assignments from class-body bytecode."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import dis
    import types
    from collections.abc import Callable

_CALL_SLICE_NOOPS: Final[frozenset[str]] = frozenset(
    (
        "CACHE",
        "COPY_FREE_VARS",
        "LOAD_LOCALS",
        "PRECALL",
        "PUSH_NULL",
        "RESUME",
    ),
)


def class_body_descriptor_assignments(
    class_body: types.CodeType,
    name_lookup: Callable[[str], object | None],
) -> dict[str, tuple[SymbolicValue, tuple[object, ...] | None]]:
    """Return statically visible ``name = Descriptor(<literal args>)`` assignments.

    Only direct calls to already-modeled class values are retained. Dynamic factories,
    keyword arguments, and non-literal constructor arguments remain unsupported so the
    descriptor protocol does not gain invented state.
    """
    instructions = list(get_instructions(class_body))
    assignments: dict[str, tuple[SymbolicValue, tuple[object, ...] | None]] = {}
    for store_index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or not isinstance(instr.argval, str):
            continue
        assignment = _assignment_before_store(instructions, store_index, name_lookup)
        if assignment is not None:
            assignments[instr.argval] = assignment
    return assignments


def _assignment_before_store(
    instructions: list[dis.Instruction],
    store_index: int,
    name_lookup: Callable[[str], object | None],
) -> tuple[SymbolicValue, tuple[object, ...] | None] | None:
    boundary = _previous_store_index(instructions, store_index)
    meaningful = [
        instr
        for instr in instructions[boundary + 1 : store_index]
        if instr.opname not in _CALL_SLICE_NOOPS
    ]
    if not meaningful or meaningful[-1].opname != "CALL":
        return None
    call = meaningful[-1]
    arg_count = call.arg
    if arg_count is None or arg_count < 0:
        return None
    operands = meaningful[:-1]
    if len(operands) != arg_count + 1:
        return None
    callee = operands[0]
    if callee.opname not in {
        "LOAD_CLASSDEREF",
        "LOAD_DEREF",
        "LOAD_FAST",
        "LOAD_FAST_CHECK",
        "LOAD_FROM_DICT_OR_DEREF",
        "LOAD_GLOBAL",
        "LOAD_NAME",
    } or not isinstance(callee.argval, str):
        return None
    descriptor_value = name_lookup(callee.argval)
    if not isinstance(descriptor_value, SymbolicValue):
        return None
    constructor_args = _literal_constructor_args(operands[1:])
    if constructor_args is None:
        return None
    return descriptor_value, constructor_args


def _previous_store_index(instructions: list[dis.Instruction], before_index: int) -> int:
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname in {"STORE_NAME", "STORE_GLOBAL"}:
            return index
    return -1


def _literal_constructor_args(instructions: list[dis.Instruction]) -> tuple[object, ...] | None:
    values: list[object] = []
    for instr in instructions:
        if instr.opname != "LOAD_CONST":
            return None
        value = instr.argval
        if not isinstance(value, (bool, int, float, str, bytes, type(None))):
            return None
        values.append(value)
    return tuple(values)
