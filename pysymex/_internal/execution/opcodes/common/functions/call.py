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

"""CALL and related function opcode dispatch for the common handler layer.

Resolves call layout, applies stdlib and builtin models, forks ``None``-callable
error paths, and falls back to havoc for unmodeled targets. Delegates attribute,
import, and ``MAKE_FUNCTION`` opcodes to sibling modules under this package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.guards.callability import handle_definite_non_callable_call
from pysymex._internal.execution.calls.guards.solver import is_uninterpreted_bool_const
from pysymex._internal.execution.calls.guards.stack import (
    is_call_null_marker,
    require_call_stack_depth,
)
from pysymex._internal.execution.calls.object.maps import is_symbolic_module_receiver
from pysymex._internal.execution.calls.target.fallbacks import CallFallbackEvents
from pysymex._internal.execution.calls.value.coercion import coerce_kw_names
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
from pysymex._internal.execution.opcodes.common.lowering.calls import CallLowerer
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.typing.protocols import StackValue

_CALL_TARGET_NONE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=CallFallbackEvents.CALL_TARGET_NONE_FEASIBILITY_UNKNOWN,
    owner="execution.calls",
    subject="callable-None",
)


def _is_modeled_context_exit(value: object) -> bool:
    """Return whether *value* represents a modeled context manager ``__exit__``."""
    method = getattr(value, "method", None)
    return getattr(value, "name", "") == "__exit__" or getattr(method, "name", "") == "__exit__"


def _pop_call_arguments(
    state: VMState,
    argc: int,
) -> tuple[list[StackValue], dict[str, StackValue]]:
    """Pop positional and keyword call arguments from the VM stack."""
    args: list[StackValue] = [state.pop() for _ in range(argc)]
    if len(args) > 1:
        args.reverse()

    kwargs: dict[str, StackValue] = {}
    kw_names_raw = state.pending_kw_names
    if kw_names_raw is not None:
        kw_names = coerce_kw_names(kw_names_raw)
        kw_count = len(kw_names)
        if len(args) >= kw_count:
            kw_vals = args[-kw_count:]
            args = args[:-kw_count]
            kwargs = dict(zip(kw_names, kw_vals, strict=False))
        state.pending_kw_names = None
    return args, kwargs


def _pop_call_target_layout_operands(
    state: VMState,
    lowerer: CallLowerer,
) -> tuple[object, StackValue, bool]:
    """Pop CALL target operands before lowerer layout normalization."""
    top_value = state.pop()
    receiver_or_null: StackValue = SymbolicNoneType()
    receiver_is_argument = False

    if not state.stack:
        return top_value, receiver_or_null, receiver_is_argument

    peeked = state.peek()
    from pysymex._internal.core.types.base import SymbolicType

    if is_call_null_marker(peeked) and (
        lowerer.is_likely_callable(top_value) or isinstance(top_value, SymbolicType)
    ):
        state.pop()
        return top_value, receiver_or_null, receiver_is_argument
    if lowerer.is_likely_callable(top_value) and lowerer.is_likely_callable(peeked):
        return state.pop(), top_value, receiver_is_argument
    if not lowerer.is_likely_callable(top_value):
        func_obj = state.pop()
        return func_obj, top_value, _is_modeled_context_exit(func_obj)
    return top_value, state.pop(), receiver_is_argument


def _handle_none_call_target(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver_or_null: StackValue,
) -> OpcodeResult:
    """Handle a definitely missing call target after CALL stack layout decoding."""
    if not isinstance(receiver_or_null, SymbolicNoneType) and receiver_or_null is not None:
        msg = "CALL stack is malformed: callable slot is NULL"
        raise VMStateError(msg)
    non_callable_result = handle_definite_non_callable_call(instr, state, ctx, None)
    if non_callable_result is not None:
        return non_callable_result
    return OpcodeResult.terminate()


def _call_symbolic_with_none_branch(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    layout_func: SymbolicValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    fallback_events: list[FallbackEvent],
) -> tuple[OpcodeResult | None, VMState]:
    """Handle symbolic call targets that may also be ``None``."""
    from pysymex._internal.execution.calls.target.dispatch.resolved import dispatch_resolved_call

    lowerer = CallLowerer(state.pc)
    is_none = lowerer.emit_none_check(layout_func)
    handler_pc = ctx.find_exception_handler(instr.offset)
    non_none_constraint = z3.Not(is_none)
    known_prefix = StateConstraints.known_sat_prefix_len(state)
    success_result = PathSatisfiability.result(
        [*state.path_constraints, non_none_constraint],
        known_sat_prefix_len=known_prefix,
    )
    raise_result = PathSatisfiability.result(
        [*state.path_constraints, is_none],
        known_sat_prefix_len=known_prefix,
    )
    can_succeed = may_be_feasible(success_result)
    can_raise = may_be_feasible(raise_result)
    fallback_events.extend(
        unknown_feasibility_events(
            state=state,
            spec=_CALL_TARGET_NONE_FEASIBILITY_SPEC,
            branches=[
                FeasibilityBranch("none", raise_result),
                FeasibilityBranch("non_none", success_result),
            ],
        ),
    )
    degraded_passes = degraded_passes_from_events(fallback_events)

    if handler_pc is None and is_uninterpreted_bool_const(is_none) and can_succeed:
        state = state.add_constraint(non_none_constraint)
        result = dispatch_resolved_call(instr, state, ctx, layout_func, args, kwargs)
        return append_fallback_events(result, fallback_events), state

    if can_raise and not can_succeed:
        if raise_result.is_unknown:
            return terminal_result_with_events(fallback_events), state
        error_state = state.fork().add_constraint(is_none)
        non_callable_result = handle_definite_non_callable_call(instr, error_state, ctx, None)
        if non_callable_result is not None:
            return append_fallback_events(non_callable_result, fallback_events), state
        return terminal_result_with_events(fallback_events), state

    if can_raise and handler_pc is not None:
        error_result = handle_definite_non_callable_call(
            instr,
            state.fork().add_constraint(is_none),
            ctx,
            None,
        )
        state = state.fork().add_constraint(non_none_constraint)
        result = dispatch_resolved_call(instr, state, ctx, layout_func, args, kwargs)
        error_states = error_result.new_states if error_result is not None else []
        error_issues = error_result.issues if error_result is not None else []
        branch_fallback_events = [*result.fallback_events, *fallback_events]
        branch_degraded_passes = [*result.degraded_passes, *degraded_passes]
        if result.new_states:
            return (
                OpcodeResult.branch(
                    [*result.new_states, *error_states],
                    [*result.issues, *error_issues],
                    branch_degraded_passes,
                    branch_fallback_events,
                ),
                state,
            )
        return (
            OpcodeResult.branch(
                error_states,
                [*result.issues, *error_issues],
                branch_degraded_passes,
                branch_fallback_events,
            ),
            state,
        )

    if can_raise:
        state = state.add_constraint(non_none_constraint)
    return None, state


def handle_common_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    from pysymex._internal.execution.calls.target.dispatch.resolved import dispatch_resolved_call

    argc = int(instr.argval) if instr.argval else 0
    require_call_stack_depth(state, instr, argc + 1, "CALL arguments plus callable")
    args, kwargs = _pop_call_arguments(state, argc)
    require_call_stack_depth(state, instr, 1, "callable after argument pop")

    lowerer = CallLowerer(state.pc)
    func_obj, receiver_or_null, receiver_is_argument = _pop_call_target_layout_operands(
        state,
        lowerer,
    )
    if func_obj is None:
        return _handle_none_call_target(instr, state, ctx, receiver_or_null)

    if is_symbolic_module_receiver(receiver_or_null, state):
        receiver_or_null = SymbolicNoneType()
    layout = lowerer.resolve_layout(
        cast("StackValue", func_obj),
        receiver_or_null,
        args,
        kwargs,
        receiver_is_argument=receiver_is_argument,
    )

    non_callable_result = handle_definite_non_callable_call(instr, state, ctx, layout.func_obj)
    if non_callable_result is not None:
        return non_callable_result

    fallback_events: list[FallbackEvent] = []
    if isinstance(layout.func_obj, SymbolicValue):
        symbolic_result, state = _call_symbolic_with_none_branch(
            instr,
            state,
            ctx,
            layout.func_obj,
            layout.args,
            layout.kwargs,
            fallback_events,
        )
        if symbolic_result is not None:
            return symbolic_result

    return append_fallback_events(
        dispatch_resolved_call(instr, state, ctx, layout.func_obj, layout.args, layout.kwargs),
        fallback_events,
    )
