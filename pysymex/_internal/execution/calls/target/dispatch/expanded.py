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

"""Expanded call-target dispatch after opcode-specific stack lowering."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.target.dispatch.resolved import dispatch_resolved_call
from pysymex._internal.execution.calls.target.fallbacks import CallFallbackEvents
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    degraded_passes_from_events,
    may_be_feasible,
    terminal_result_with_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

_CALL_TARGET_NONE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=CallFallbackEvents.CALL_TARGET_NONE_FEASIBILITY_UNKNOWN,
    owner="execution.calls",
    subject="callable-None",
)


def dispatch_expanded_call_target(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Dispatch an already expanded call target after opcode-specific stack lowering."""
    from pysymex._internal.execution.calls.guards.callability import (
        handle_definite_non_callable_call,
    )

    non_callable_result = handle_definite_non_callable_call(instr, state, ctx, func_obj)
    if non_callable_result is not None:
        return non_callable_result

    fallback_events = []
    if isinstance(func_obj, SymbolicValue):
        is_none = func_obj.is_none
        non_none = z3.Not(is_none)
        known_prefix = StateConstraints.known_sat_prefix_len(state)
        raise_result = PathSatisfiability.result(
            [*state.path_constraints, is_none],
            known_sat_prefix_len=known_prefix,
        )
        success_result = PathSatisfiability.result(
            [*state.path_constraints, non_none],
            known_sat_prefix_len=known_prefix,
        )
        can_raise = may_be_feasible(raise_result)
        can_succeed = may_be_feasible(success_result)
        fallback_events = unknown_feasibility_events(
            state=state,
            spec=_CALL_TARGET_NONE_FEASIBILITY_SPEC,
            branches=[
                FeasibilityBranch("none", raise_result),
                FeasibilityBranch("non_none", success_result),
            ],
        )
        degraded_passes = degraded_passes_from_events(fallback_events)
        handler_pc = ctx.find_exception_handler(instr.offset)

        if can_raise and not can_succeed:
            if raise_result.is_unknown:
                return terminal_result_with_events(fallback_events)
            error_state = state.fork().add_constraint(is_none)
            non_callable_result = handle_definite_non_callable_call(instr, error_state, ctx, None)
            if non_callable_result is not None:
                return append_fallback_events(non_callable_result, fallback_events)
            return terminal_result_with_events(fallback_events)

        if can_raise and handler_pc is not None:
            error_result = handle_definite_non_callable_call(
                instr,
                state.fork().add_constraint(is_none),
                ctx,
                None,
            )
            normal_state = state.fork().add_constraint(non_none)
            normal_result = dispatch_resolved_call(instr, normal_state, ctx, func_obj, args, kwargs)
            error_states = error_result.new_states if error_result is not None else []
            error_issues = error_result.issues if error_result is not None else []
            if normal_result.new_states:
                return OpcodeResult.branch(
                    [*normal_result.new_states, *error_states],
                    [*normal_result.issues, *error_issues],
                    [*normal_result.degraded_passes, *degraded_passes],
                    [*normal_result.fallback_events, *fallback_events],
                )
            return OpcodeResult.branch(
                error_states,
                [*normal_result.issues, *error_issues],
                [*normal_result.degraded_passes, *degraded_passes],
                [*normal_result.fallback_events, *fallback_events],
            )

        if can_raise:
            state = state.add_constraint(non_none)

    result = dispatch_resolved_call(instr, state, ctx, func_obj, args, kwargs)
    if isinstance(func_obj, SymbolicValue):
        return append_fallback_events(result, fallback_events)
    return result
