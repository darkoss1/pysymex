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

"""Modeled ``__index__`` protocol continuations for native collection opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.containers.slices import extract_slice_bounds, replace_slice_bound
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def route_modeled_index(
    state: VMState,
    ctx: OpcodeDispatcher,
    preserved_operands: list[StackValue],
    index: StackValue,
) -> OpcodeResult | None:
    """Suspend a native subscript while executing ``index.__index__()``."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(index, "__index__")
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
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
            CollectionFallbackEvents.unsupported_subscript(
                state=state,
                reason="modeled __index__ for subscript could not be entered",
            ),
        ],
        terminal=True,
    )


def route_modeled_slice_index(
    state: VMState,
    ctx: OpcodeDispatcher,
    preserved_operands: list[StackValue],
    start: StackValue,
    stop: StackValue,
) -> OpcodeResult | None:
    """Suspend a native slice opcode around ordered ``__index__`` evaluation."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    start_method = lookup_modeled_method(start, "__index__")
    if start_method is not None:
        for operand in preserved_operands:
            state = state.push(operand)
        from pysymex._internal.execution.calls.interprocedural.entry import (
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
                CollectionFallbackEvents.unsupported_subscript(
                    state=state,
                    reason="modeled __index__ for slice start could not be entered",
                ),
            ],
            terminal=True,
        )
    stop_method = lookup_modeled_method(stop, "__index__")
    if stop_method is None:
        return None
    for operand in preserved_operands:
        state = state.push(operand)
    state = state.push(start)
    from pysymex._internal.execution.calls.interprocedural.entry import (
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
            CollectionFallbackEvents.unsupported_subscript(
                state=state,
                reason="modeled __index__ for slice stop could not be entered",
            ),
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
        msg = "Missing retained slice-stop continuation operand"
        raise VMStateError(msg)
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
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

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
        from pysymex._internal.execution.calls.interprocedural.entry import (
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
                CollectionFallbackEvents.unsupported_subscript(
                    state=state,
                    reason=f"modeled __index__ for built-slice {component} could not be entered",
                ),
            ],
            terminal=True,
        )
    return None


def complete_retained_built_slice_index(
    frame: CallFrame,
    return_value: StackValue,
    state: VMState,
) -> OpcodeResult:
    """Replace one consumed bound and resume a native ``BINARY_SUBSCR``."""
    carrier = frame.protocol_retained_operand
    if not isinstance(carrier, SymbolicValue):
        msg = "Missing retained BUILD_SLICE continuation carrier"
        raise VMStateError(msg)
    components = {
        "__index_built_slice_start__": "start",
        "__index_built_slice_stop__": "stop",
        "__index_built_slice_step__": "step",
    }
    component = components.get(frame.protocol_method or "")
    if component is None:
        msg = "Unknown BUILD_SLICE continuation component"
        raise VMStateError(msg)
    try:
        updated = replace_slice_bound(carrier, component, return_value)
    except ValueError as exc:
        msg = "Missing retained BUILD_SLICE bounds"
        raise VMStateError(msg) from exc
    state = state.push(updated)
    return OpcodeResult.continue_with(state)
