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

"""UNPACK_EX starred-target opcode semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import fresh_name
from pysymex._internal.core.types.capabilities import length_expr
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_unpack_ex(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Unpack with starred target."""
    CollectionStackOps.require_depth(state, instr, 1, "UNPACK_EX source")
    container = SymbolicObject.resolve_stack_value(state, state.pop())
    arg = int(instr.argval) if instr.argval else 0
    before = arg & 0xFF
    after = (arg >> 8) & 0xFF

    sequence = ConcreteExtractionPolicy.sequence(container)
    if sequence is not None:
        actual = len(sequence)
        required = before + after
        if actual < required:
            return CollectionStackOps.unpack_arity_error(
                instr,
                state,
                ctx,
                expected=required,
                actual=actual,
            )

        concrete_output_values: list[StackValue] = []
        concrete_output_values.extend(StackValuePolicy.coerce(item) for item in sequence[:before])
        star_stop = actual - after if after else actual
        concrete_output_values.append(
            [StackValuePolicy.coerce(item) for item in sequence[before:star_stop]],
        )
        if after:
            concrete_output_values.extend(
                StackValuePolicy.coerce(item) for item in sequence[-after:]
            )

        for value in reversed(concrete_output_values):
            state = state.push(value)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    symbolic_output_values: list[StackValue] = []
    for i in range(before):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_before_{i}")
            state = state.add_constraint(constraint)
        symbolic_output_values.append(val)
    if isinstance(container, SymbolicList):
        required = ConstraintValues.int(before + after)
        star_idx = z3.Int(fresh_name("unpack_ex_star_idx"))
        star_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [star_idx],
                z3.Select(container.z3_array, star_idx + ConstraintValues.int(before)),
            ),
        )
        star = SymbolicList(
            _name=f"unpack_ex_{state.pc}_star",
            z3_array=star_array,
            z3_len=container.z3_len - required,
            element_type=container.element_type,
        )
        state = state.add_constraint(container.z3_len >= required)
        state = state.add_constraint(star.z3_len >= 0)
    else:
        star, star_constraint = SymbolicList.symbolic(f"unpack_ex_{state.pc}_star")
        state = state.add_constraint(star_constraint)
        container_len = length_expr(container)
        if container_len is not None:
            required = ConstraintValues.int(before + after)
            star.z3_len = container_len - required
            state = state.add_constraint(container_len >= required)
            state = state.add_constraint(star.z3_len >= 0)
    symbolic_output_values.append(star)
    for i in range(after):
        if isinstance(container, SymbolicList):
            item_index = container.z3_len - ConstraintValues.int(after - i)
            val = SymbolicValue(
                _name=f"unpack_ex_{state.pc}_after_{i}",
                z3_int=cast("z3.ArithRef", z3.Select(container.z3_array, item_index)),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_after_{i}")
            state = state.add_constraint(constraint)
        symbolic_output_values.append(val)
    for value in reversed(symbolic_output_values):
        state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
