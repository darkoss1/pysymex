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

"""Complete suspended ``__contains__`` / membership truth protocol calls.

After a modeled membership dunder returns, coerces the result to a CPython boolean on
the stack (including negated ``not in`` variants) and may fork feasible truth paths via
:mod:`pysymex.execution.opcodes.common.control.feasibility`.

Limitations:
    Nested membership truth protocols only cover the combinations listed in module
    constants; unknown protocol suffixes defer to generic handling.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.state.types import VMStateError
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_ONE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.feasibility import known_sat_prefix_len_for_state
from pysymex.execution.opcodes.common.control.feasibility import (
    branch_feasible,
    get_truthy_expr,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


_MEMBERSHIP_OPERATIONS = {"__contains__", "__contains_not__"}
_NEGATED_MEMBERSHIP_OPERATIONS = {
    "__contains_not__",
    "__contains_not___truth_bool__",
    "__contains_not___truth_len__",
}
_NESTED_MEMBERSHIP_TRUTH = {
    "__contains___truth_bool__",
    "__contains___truth_len__",
    "__contains_not___truth_bool__",
    "__contains_not___truth_len__",
}


def _membership_result(value: StackValue, invert: bool, pc: int) -> SymbolicValue:
    """Coerce a membership method result to CPython's required boolean."""
    condition = get_truthy_expr(value)
    if invert:
        condition = z3.Not(condition)
    return SymbolicValue(
        _name=f"membership_{pc}",
        z3_int=z3.If(condition, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=condition,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )


def complete_retained_membership(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Truth-test a modeled ``__contains__`` result and resume its caller."""
    if return_value is None:
        return_value = SymbolicNone("membership_None")
    protocol_method = frame.protocol_method
    if protocol_method in _MEMBERSHIP_OPERATIONS:
        from pysymex.execution.opcodes.common.control.feasibility import (
            try_dispatch_modeled_truth_protocol,
        )

        truth_result = try_dispatch_modeled_truth_protocol(
            return_value,
            state,
            ctx,
            resume_pc=frame.return_pc,
            membership_operation=protocol_method,
        )
        if truth_result is not None:
            return truth_result
    elif protocol_method not in _NESTED_MEMBERSHIP_TRUTH:
        return None

    invert = protocol_method in _NEGATED_MEMBERSHIP_OPERATIONS
    state = state.push(_membership_result(return_value, invert, state.pc))
    state.depth -= 1
    return OpcodeResult.continue_with(state)


def complete_retained_truth_jump(
    frame: CallFrame,
    return_value: StackValue,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Finish a suspended ``JUMP_IF_*_OR_POP`` while preserving its operand."""
    retained_operand = frame.protocol_retained_operand
    instructions = frame.caller_instructions
    if retained_operand is None or instructions is None:
        raise VMStateError("Missing retained truth-jump continuation state")
    if frame.return_pc < 0 or frame.return_pc >= len(instructions):
        raise VMStateError("Truth-jump continuation return PC is outside caller instructions")

    instr = instructions[frame.return_pc]
    if not isinstance(instr, dis.Instruction) or instr.opname not in {
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
    }:
        raise VMStateError("Truth-jump continuation did not resume a short-circuit jump")

    cond_expr = get_truthy_expr(return_value)
    jump_on_true = instr.opname == "JUMP_IF_TRUE_OR_POP"
    jump_condition = cond_expr if jump_on_true else z3.Not(cond_expr)
    fallthrough_condition = z3.Not(jump_condition)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    branches: list[VMState] = []
    known_prefix_len = known_sat_prefix_len_for_state(state)
    if branch_feasible(
        state.path_constraints,
        jump_condition,
        known_sat_prefix_len=known_prefix_len,
    ):
        jump_state = state.fork()
        jump_state = jump_state.push(retained_operand)
        jump_state = jump_state.add_constraint(jump_condition)
        jump_state = jump_state.record_branch(cond_expr, jump_on_true, frame.return_pc)
        jump_state = jump_state.set_pc(target_index)
        branches.append(jump_state)
    if branch_feasible(
        state.path_constraints,
        fallthrough_condition,
        known_sat_prefix_len=known_prefix_len,
    ):
        fallthrough_state = state.fork()
        fallthrough_state = fallthrough_state.add_constraint(fallthrough_condition)
        fallthrough_state = fallthrough_state.record_branch(
            cond_expr, not jump_on_true, frame.return_pc
        )
        fallthrough_state = fallthrough_state.set_pc(frame.return_pc + 1)
        branches.append(fallthrough_state)
    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


__all__ = ["complete_retained_membership", "complete_retained_truth_jump"]
