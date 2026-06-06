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

"""Modeled ``__getitem__``, ``__index__``, and slice protocol dispatch for collections.

Suspends native subscript and slice opcodes to run interprocedural modeled methods,
then resumes with retained operands. Returns terminal unsupported results when
protocol continuation cannot be established.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.types import VMStateError
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.fallbacks import (
    collection_fallback_events,
    unsupported_subscript_event,
)
from pysymex.execution.opcodes.common.collections.helpers import path_is_sat
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
    extract_slice_bounds,
    possible_zero_step_condition,
    replace_slice_bound,
)
from pysymex.execution.opcodes.common.lowering.types import UNSUPPORTED_SUBSCRIPT_ABSTRACTION

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def dispatch_modeled_subscript_protocol(
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    method_name: str,
    args: list[StackValue],
) -> OpcodeResult | None:
    """Enter a custom subscript method when the container defines one."""
    if not isinstance(container, SymbolicValue):
        return None
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(container, method_name)
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [container, *args],
        {},
        protocol_method=method_name,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        fallback_events=[
            unsupported_subscript_event(
                state=state,
                reason=f"modeled subscript method {method_name!r} could not be entered",
            )
        ],
        terminal=True,
    )


def dispatch_modeled_index_protocol(
    state: VMState,
    ctx: OpcodeDispatcher,
    preserved_operands: list[StackValue],
    index: StackValue,
) -> OpcodeResult | None:
    """Suspend a native subscript while executing ``index.__index__()``."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(index, "__index__")
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    for operand in preserved_operands:
        state = state.push(operand)
    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [],
        {},
        protocol_method="__index_subscr__",
        resume_pc=state.pc,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        fallback_events=[
            unsupported_subscript_event(
                state=state,
                reason="modeled __index__ for subscript could not be entered",
            )
        ],
        terminal=True,
    )


def dispatch_modeled_slice_index_protocol(
    state: VMState,
    ctx: OpcodeDispatcher,
    preserved_operands: list[StackValue],
    start: StackValue,
    stop: StackValue,
) -> OpcodeResult | None:
    """Suspend a native slice opcode around ordered ``__index__`` evaluation."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    start_method = lookup_modeled_method(start, "__index__")
    if start_method is not None:
        for operand in preserved_operands:
            state = state.push(operand)
        from pysymex.execution.calls.interprocedural import (
            perform_interprocedural_call_impl,
        )

        result = perform_interprocedural_call_impl(
            state,
            ctx,
            start_method,
            [],
            {},
            protocol_method="__index_slice_start__",
            resume_pc=state.pc,
            protocol_retained_operand=stop,
        )
        if result is not None:
            return result
        return OpcodeResult(
            new_states=[],
            issues=[],
            degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
            fallback_events=[
                unsupported_subscript_event(
                    state=state,
                    reason="modeled __index__ for slice start could not be entered",
                )
            ],
            terminal=True,
        )
    stop_method = lookup_modeled_method(stop, "__index__")
    if stop_method is None:
        return None
    for operand in preserved_operands:
        state = state.push(operand)
    state = state.push(start)
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        stop_method,
        [],
        {},
        protocol_method="__index_slice_stop__",
        resume_pc=state.pc,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        fallback_events=[
            unsupported_subscript_event(
                state=state,
                reason="modeled __index__ for slice stop could not be entered",
            )
        ],
        terminal=True,
    )


def complete_retained_slice_index(
    frame: CallFrame,
    return_value: StackValue,
    state: VMState,
) -> OpcodeResult:
    """Rebuild slice opcode operands after start-bound conversion."""
    retained_operand = frame.protocol_retained_operand
    if retained_operand is None:
        raise VMStateError("Missing retained slice-stop continuation operand")
    state = state.push(return_value)
    state = state.push(retained_operand)
    return OpcodeResult.continue_with(state)


def dispatch_built_slice_index_protocol(
    state: VMState,
    ctx: OpcodeDispatcher,
    preserved_operands: list[StackValue],
    index: SymbolicValue,
) -> OpcodeResult | None:
    """Consume a ``BUILD_SLICE`` carrier through native ``__index__`` calls."""
    bounds = extract_slice_bounds(index)
    if bounds is None:
        return None
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    # CPython normalizes extended slice bounds as step, start, then stop.
    for component, bound in (
        ("step", bounds.step),
        ("start", bounds.start),
        ("stop", bounds.stop),
    ):
        if bound is None:
            continue
        method = lookup_modeled_method(bound, "__index__")
        if method is None:
            continue
        for operand in preserved_operands:
            state = state.push(operand)
        from pysymex.execution.calls.interprocedural import (
            perform_interprocedural_call_impl,
        )

        result = perform_interprocedural_call_impl(
            state,
            ctx,
            method,
            [],
            {},
            protocol_method=f"__index_built_slice_{component}__",
            resume_pc=state.pc,
            protocol_retained_operand=index,
        )
        if result is not None:
            return result
        return OpcodeResult(
            new_states=[],
            issues=[],
            degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
            fallback_events=[
                unsupported_subscript_event(
                    state=state,
                    reason=f"modeled __index__ for built-slice {component} could not be entered",
                )
            ],
            terminal=True,
        )
    return None


def retained_slice_value_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str = "slice step cannot be zero",
    degraded_passes: list[str] | None = None,
) -> OpcodeResult:
    """Branch or error on a concrete ``ValueError`` for invalid retained slice bounds."""
    modeled_exc = SymbolicException.concrete(ValueError, message, raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    fallback_events = collection_fallback_events(
        state=state,
        degraded_passes=degraded_passes or [],
        reason="retained slice zero-step condition is possible but not definite",
    )
    if handler_state is not None:
        return OpcodeResult.continue_with(
            handler_state,
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.VALUE_ERROR,
            message=f"Possible ValueError: {message}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def dispatch_retained_slice_zero_step(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    index: SymbolicValue,
) -> OpcodeResult | None:
    """Report or route the feasible ``step == 0`` path of a retained slice."""
    condition = possible_zero_step_condition(index)
    if condition is None or not path_is_sat([*state.path_constraints, condition]):
        return None
    is_definite = z3.is_true(z3.simplify(condition))
    error_state = state.fork().add_constraint(condition)
    return retained_slice_value_error_result(
        instr,
        error_state,
        ctx,
        degraded_passes=None if is_definite else [UNSUPPORTED_SLICE_ABSTRACTION],
    )


def complete_retained_built_slice_index(
    frame: CallFrame,
    return_value: StackValue,
    state: VMState,
) -> OpcodeResult:
    """Replace one consumed bound and resume a native ``BINARY_SUBSCR``."""
    carrier = frame.protocol_retained_operand
    if not isinstance(carrier, SymbolicValue):
        raise VMStateError("Missing retained BUILD_SLICE continuation carrier")
    components = {
        "__index_built_slice_start__": "start",
        "__index_built_slice_stop__": "stop",
        "__index_built_slice_step__": "step",
    }
    component = components.get(frame.protocol_method or "")
    if component is None:
        raise VMStateError("Unknown BUILD_SLICE continuation component")
    try:
        updated = replace_slice_bound(carrier, component, return_value)
    except ValueError as exc:
        raise VMStateError("Missing retained BUILD_SLICE bounds") from exc
    state = state.push(updated)
    return OpcodeResult.continue_with(state)


__all__ = [
    "complete_retained_built_slice_index",
    "complete_retained_slice_index",
    "dispatch_built_slice_index_protocol",
    "dispatch_modeled_index_protocol",
    "dispatch_modeled_slice_index_protocol",
    "dispatch_modeled_subscript_protocol",
    "dispatch_retained_slice_zero_step",
    "retained_slice_value_error_result",
]
