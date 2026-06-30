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

"""Modeled generator-expression exception effects for ``sum()``."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.arithmetic import tagged_numeric_zero_condition
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult

from .sources import generator_code, generator_items

if TYPE_CHECKING:
    import dis
    import types

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.generators import ModeledGenerator


def modeled_generator_sum(
    *,
    name: str,
    generator: ModeledGenerator,
    state: VMState,
) -> ModelResult | None:
    """Return a symbolic ``sum`` result with generator division side effects."""
    code = generator_code(generator)
    items = generator_items(generator, state)
    if code is None or items is None:
        return None
    if not _simple_unfiltered_division_yield(code):
        return None

    zero_conditions: list[z3.BoolRef] = []
    for item in items:
        condition = _zero_condition(item)
        if condition is None:
            return None
        if not z3.is_false(simplify_expr(condition)):
            zero_conditions.append(condition)
    if not zero_conditions:
        return None

    condition = simplify_expr(z3.Or(*zero_conditions))
    return ModelResult.int(
        f"{name}_{state.pc}",
        side_effects={
            "potential_exception": {
                "type": "ZeroDivisionError",
                "message": "generator expression divisor can be zero",
                "condition": condition,
            },
        },
    )


def _simple_unfiltered_division_yield(code: types.CodeType) -> bool:
    instructions = list(get_instructions(code))
    if _has_filter_jump(instructions):
        return False
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE" or index < 2:
            continue
        binary = instructions[index - 1]
        divisor = instructions[index - 2]
        return (
            binary.opname == "BINARY_OP"
            and resolve_binary_op_symbol(binary) in {"/", "//"}
            and divisor.opname in {"LOAD_FAST", "LOAD_FAST_CHECK"}
        )
    return False


def _has_filter_jump(instructions: list[dis.Instruction]) -> bool:
    for instruction in instructions:
        opname = instruction.opname
        if opname.startswith(("POP_JUMP", "JUMP_IF")):
            return True
    return False


def _zero_condition(item: object) -> z3.BoolRef | None:
    if isinstance(item, bool):
        return Z3_FALSE if item else Z3_TRUE
    if isinstance(item, int):
        return Z3_TRUE if item == 0 else Z3_FALSE
    if not isinstance(item, SymbolicValue):
        return None
    return tagged_numeric_zero_condition(
        concrete_value=item.value,
        affinity_type=item.affinity_type,
        is_int=item.is_int,
        int_expr=item.z3_int,
        is_bool=item.is_bool,
        bool_expr=item.z3_bool,
        is_float=item.is_float,
        float_expr=item.z3_float,
        include_float=True,
    )
