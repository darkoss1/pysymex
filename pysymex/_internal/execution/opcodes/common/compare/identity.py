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

"""Identity comparison semantics for ``IS_OP``."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.compare.exact import exact_bool_identity_condition
from pysymex._internal.execution.opcodes.common.compare.guards import require_compare_stack_depth

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_is_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Identity comparison (is / is not)."""
    require_compare_stack_depth(state, instr, 2, "IS_OP operands")
    right = state.pop()
    left = state.pop()
    invert = bool(instr.argval)
    left_is_none = isinstance(left, SymbolicNoneType) or (
        isinstance(left, SymbolicValue) and z3.is_true(left.is_none)
    )
    right_is_none = isinstance(right, SymbolicNoneType) or (
        isinstance(right, SymbolicValue) and z3.is_true(right.is_none)
    )

    if left_is_none or right_is_none:
        if left_is_none and right_is_none:
            is_same = Z3_TRUE
        elif left_is_none and isinstance(right, SymbolicValue):
            is_same = right.is_none
        elif right_is_none and isinstance(left, SymbolicValue):
            is_same = left.is_none
        else:
            is_same = Z3_FALSE
    else:
        exact_bool_identity = exact_bool_identity_condition(left, right)
        if exact_bool_identity is not None:
            is_same = exact_bool_identity
        elif isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
            is_same = left.z3_addr == right.z3_addr
        elif isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
            is_same = z3.And(
                z3.Implies(z3.And(left.is_obj, right.is_obj), left.z3_addr == right.z3_addr),
                z3.Implies(z3.And(left.is_int, right.is_int), left.z3_int == right.z3_int),
                z3.Implies(z3.And(left.is_str, right.is_str), left.z3_str == right.z3_str),
                left.is_int == right.is_int,
                left.is_obj == right.is_obj,
                left.is_str == right.is_str,
            )
        elif isinstance(left, SymbolicValue) and isinstance(right, bool):
            is_same = z3.And(left.is_bool, left.z3_bool == right)
        elif isinstance(right, SymbolicValue) and isinstance(left, bool):
            is_same = z3.And(right.is_bool, right.z3_bool == left)
        else:
            is_same = Z3_TRUE if left is right else Z3_FALSE

    result_bool = z3.Not(is_same) if invert else is_same
    result = SymbolicValue(
        _name=f"({'is not' if invert else 'is'}_{state.pc})",
        z3_int=z3.If(result_bool, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=result_bool,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
