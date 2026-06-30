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

"""Ordered resolved-target dispatch for models, summaries, functions, and havoc."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.classes.allocation import try_modeled_object_allocation
from pysymex._internal.execution.calls.classes.construction import try_modeled_class_call
from pysymex._internal.execution.calls.havoc import (
    UNMODELED_CALL_ABSTRACTION,
    create_unmodeled_call_havoc,
)
from pysymex._internal.execution.calls.interprocedural.entry import (
    perform_interprocedural_call_impl,
)
from pysymex._internal.execution.calls.model.dispatch import apply_model
from pysymex._internal.execution.calls.target.fallbacks import CallFallbackEvents
from pysymex._internal.execution.calls.target.specials.dispatch import dispatch_special_call_target
from pysymex._internal.execution.calls.target.summaries import dispatch_summary_call_target
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_resolved_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Apply models, summaries, interprocedural calls, or havoc for one resolved target."""
    special_result = dispatch_special_call_target(instr, state, ctx, func_obj, args, kwargs)
    if special_result is not None:
        return special_result

    result = apply_model(state, func_obj, args, kwargs, ctx, instr)
    if result:
        return result

    allocation_result = try_modeled_object_allocation(state, func_obj, args, kwargs)
    if allocation_result is not None:
        return allocation_result

    oop_result = try_modeled_class_call(instr, state, ctx, func_obj, args, kwargs)
    if oop_result is not None:
        return oop_result

    if isinstance(func_obj, SymbolicValue):
        from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

        call_method = lookup_modeled_method(func_obj, "__call__")
        if call_method is not None:
            call_result = perform_interprocedural_call_impl(
                state,
                ctx,
                call_method,
                [func_obj, *args],
                kwargs,
            )
            if call_result is not None:
                return call_result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[CallFallbackEvents.UNSUPPORTED_CALL_PROTOCOL],
                fallback_events=[CallFallbackEvents.unsupported_call_protocol(state=state)],
                terminal=True,
            )

    call_name = CallFallbackEvents.target_name(func_obj)
    summary_result = dispatch_summary_call_target(state, ctx, call_name, args, kwargs)
    if summary_result is not None:
        return summary_result

    result = perform_interprocedural_call_impl(state, ctx, func_obj, args, kwargs)
    if result:
        return result

    fallback_event = CallFallbackEvents.unmodeled_call_havoc(state=state, call_name=call_name)
    ret, tc = create_unmodeled_call_havoc(state, func_obj)
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()

    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNMODELED_CALL_ABSTRACTION],
        fallback_events=[fallback_event],
    )
