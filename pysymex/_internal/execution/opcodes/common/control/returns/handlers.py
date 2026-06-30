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

"""``RETURN_VALUE`` lowering, summary cache interaction, and caller restoration.

Restores the caller stack frame, applies return-contract normalization for modeled
protocols, and merges independently routed exception branches. Does not own ordinary
forward control flow (see :mod:`pysymex._internal.execution.opcodes.common.control.feasibility`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.protocol.returns.core import ProtocolReturns
from pysymex._internal.execution.opcodes.common.control.returns.results import (
    combine_return_results,
    degraded_protocol_return_result,
    with_return_issues,
)
from pysymex._internal.execution.opcodes.common.control.returns.state import (
    apply_argument_alias_updates,
    apply_write_event_scope_updates,
    collect_return_postcondition_issues,
    restore_caller_stack,
)
from pysymex._internal.execution.opcodes.common.control.returns.summaries import (
    store_return_summary_if_supported,
)

_DISCARDED_MUTATION_RETURNS = {
    "__setitem__",
    "__delitem__",
    "__setattr__",
    "__delattr__",
    "__descriptor_set__",
    "__descriptor_delete__",
}
_BUILTIN_MUTATION_RETURNS = {
    "__builtin_setattr__",
    "__builtin_delattr__",
    "__builtin_descriptor_set__",
    "__builtin_descriptor_delete__",
}


if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_return_const(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a constant with shared interprocedural and protocol handling."""
    expected_function_name = state.call_stack[-1].function_name if state.call_stack else None
    return_value = (
        SymbolicNoneType("return_None")
        if instr.argval is None
        else SymbolicValue.from_const(instr.argval)
    )
    contract_issues = collect_return_postcondition_issues(
        state,
        return_value,
        getattr(ctx, "config", None),
        expected_function_name=expected_function_name,
    )

    frame = state.pop_call()
    protocol_issue = None
    degraded_pass = None
    if frame is not None:
        return_value, protocol_issue, degraded_pass = ProtocolReturns.truth(
            frame,
            return_value,
            state,
        )
    if degraded_pass is not None:
        return degraded_protocol_return_result(state, degraded_pass)
    if frame is None:
        if contract_issues or protocol_issue:
            return OpcodeResult(
                new_states=[],
                issues=[*contract_issues, *([protocol_issue] if protocol_issue else [])],
                terminal=True,
            )
        return OpcodeResult.terminate()
    from pysymex._internal.execution.opcodes.common.coroutines.lifecycle import (
        complete_coroutine_return,
    )
    from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
        complete_generator_return,
    )

    coroutine_result = complete_coroutine_return(frame, state, ctx, return_value)
    if coroutine_result is not None:
        return coroutine_result
    generator_result = complete_generator_return(frame, state, ctx, return_value)
    if generator_result is not None:
        return generator_result

    apply_write_event_scope_updates(state, frame)
    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    state = state.set_pc(frame.return_pc)
    if frame.caller_instructions is not None:
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", caller_instructions)
        ctx.set_instructions(caller_instructions)
    if protocol_issue is None:
        from pysymex._internal.execution.opcodes.common.control.returns.lifecycle import (
            continue_modeled_instance_initialization,
        )

        lifecycle_result = continue_modeled_instance_initialization(frame, return_value, state, ctx)
        if lifecycle_result is not None:
            return with_return_issues(lifecycle_result, contract_issues)
    if protocol_issue is None:
        from pysymex._internal.execution.opcodes.common.control.protocol.negotiation import (
            continue_deferred_protocol_call,
        )

        protocol_result = continue_deferred_protocol_call(frame, return_value, state, ctx)
        if protocol_result is not None:
            return with_return_issues(protocol_result, contract_issues)
    if protocol_issue is None:
        from pysymex._internal.execution.opcodes.common.control.protocol.continuations import (
            complete_retained_protocol_operation,
        )

        retained_result = complete_retained_protocol_operation(frame, return_value, state, ctx)
        if retained_result is not None:
            return with_return_issues(retained_result, contract_issues)
    if frame.protocol_method in _BUILTIN_MUTATION_RETURNS:
        state = state.push(SymbolicNoneType("return_None"))
        state.depth -= 1
        if protocol_issue:
            return with_return_issues(
                OpcodeResult(new_states=[state], issues=[protocol_issue]),
                contract_issues,
            )
        return with_return_issues(OpcodeResult.continue_with(state), contract_issues)
    if frame.protocol_method in _DISCARDED_MUTATION_RETURNS:
        state.depth -= 1
        return with_return_issues(OpcodeResult.continue_with(state), contract_issues)
    if frame.is_init_call:
        state = state.push(
            frame.init_instance
            if frame.init_instance is not None
            else SymbolicNoneType("missing_init_instance"),
        )
    else:
        state = state.push(return_value)
    state.depth -= 1
    if protocol_issue:
        return with_return_issues(
            OpcodeResult(new_states=[state], issues=[protocol_issue]),
            contract_issues,
        )
    return with_return_issues(OpcodeResult.continue_with(state), contract_issues)


def _resume_coroutine_or_generator_return(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    return_value: StackValue | None,
) -> OpcodeResult | None:
    """Complete coroutine/generator return protocols before ordinary caller restoration."""
    from pysymex._internal.execution.opcodes.common.coroutines.lifecycle import (
        complete_coroutine_return,
    )
    from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
        complete_generator_return,
    )

    coroutine_result = complete_coroutine_return(frame, state, ctx, return_value)
    if coroutine_result is not None:
        return coroutine_result
    return complete_generator_return(frame, state, ctx, return_value)


def _restore_return_caller_frame(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
) -> VMState:
    """Restore caller stack, locals, PC, and instruction stream after callee return."""
    apply_write_event_scope_updates(state, frame)
    caller_locals = apply_argument_alias_updates(state, frame)
    restore_caller_stack(state, frame)
    state.local_vars = caller_locals
    state = state.set_pc(frame.return_pc)
    if frame.caller_instructions is not None:
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", caller_instructions)
        ctx.set_instructions(caller_instructions)
    return state


def _continue_return_protocols(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
    contract_issues: list[Issue],
    length_exception_result: OpcodeResult | None,
) -> OpcodeResult | None:
    """Continue deferred lifecycle/protocol returns when no protocol issue was emitted."""
    from pysymex._internal.execution.opcodes.common.control.protocol.continuations import (
        complete_retained_protocol_operation,
    )
    from pysymex._internal.execution.opcodes.common.control.protocol.negotiation import (
        continue_deferred_protocol_call,
    )
    from pysymex._internal.execution.opcodes.common.control.returns.lifecycle import (
        continue_modeled_instance_initialization,
    )

    for result in (
        continue_modeled_instance_initialization(frame, return_value, state, ctx),
        continue_deferred_protocol_call(frame, return_value, state, ctx),
        complete_retained_protocol_operation(frame, return_value, state, ctx),
    ):
        if result is not None:
            return combine_return_results(
                with_return_issues(result, contract_issues),
                length_exception_result,
            )
    return None


def _finalize_protocol_mutation_return(
    frame: CallFrame,
    state: VMState,
    protocol_issue: Issue | None,
    contract_issues: list[Issue],
    length_exception_result: OpcodeResult | None,
) -> OpcodeResult | None:
    """Finalize return behavior for mutating protocol methods."""
    if frame.protocol_method in _BUILTIN_MUTATION_RETURNS:
        state = state.push(SymbolicNoneType("return_None"))
        state.depth -= 1
        builtin_result = (
            OpcodeResult(new_states=[state], issues=[protocol_issue])
            if protocol_issue
            else OpcodeResult.continue_with(state)
        )
        return combine_return_results(
            with_return_issues(builtin_result, contract_issues),
            length_exception_result,
        )
    if frame.protocol_method in _DISCARDED_MUTATION_RETURNS:
        state.depth -= 1
        return combine_return_results(
            with_return_issues(OpcodeResult.continue_with(state), contract_issues),
            length_exception_result,
        )
    return None


def _push_frame_return_value(
    state: VMState,
    frame: CallFrame,
    return_value: StackValue | None,
) -> VMState:
    """Push the effective caller-visible return value for normal function/init returns."""
    if frame.is_init_call:
        return state.push(
            frame.init_instance
            if frame.init_instance is not None
            else SymbolicNoneType("missing_init_instance"),
        )
    if return_value is not None:
        return state.push(return_value)
    return state.push(SymbolicNoneType("return_None"))


def _handle_return_value_with_frame(
    frame: CallFrame,
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    return_value: StackValue | None,
    contract_issues: list[Issue],
) -> OpcodeResult:
    """Handle RETURN_VALUE after a callee frame was popped."""
    del instr
    protocol_issue = None
    length_exception_result: OpcodeResult | None = None

    from pysymex._internal.execution.opcodes.common.control.returns.length import (
        fork_feasible_negative_symbolic_length,
    )

    length_fork = fork_feasible_negative_symbolic_length(frame, return_value, state, ctx)
    if length_fork is not None:
        resumed_state, length_exception_result = length_fork
        if resumed_state is None:
            return length_exception_result
        state = resumed_state
    return_value, protocol_issue, degraded_pass = ProtocolReturns.truth(frame, return_value, state)
    if degraded_pass is not None:
        return degraded_protocol_return_result(state, degraded_pass)

    store_return_summary_if_supported(frame, return_value, state, ctx)
    generator_result = _resume_coroutine_or_generator_return(frame, state, ctx, return_value)
    if generator_result is not None:
        return generator_result

    state = _restore_return_caller_frame(state, ctx, frame)
    if protocol_issue is None:
        protocol_result = _continue_return_protocols(
            frame,
            return_value,
            state,
            ctx,
            contract_issues,
            length_exception_result,
        )
        if protocol_result is not None:
            return protocol_result

    mutation_result = _finalize_protocol_mutation_return(
        frame,
        state,
        protocol_issue,
        contract_issues,
        length_exception_result,
    )
    if mutation_result is not None:
        return mutation_result

    state = _push_frame_return_value(state, frame, return_value)
    state.depth -= 1
    result = (
        OpcodeResult(new_states=[state], issues=[protocol_issue])
        if protocol_issue
        else OpcodeResult.continue_with(state)
    )
    return combine_return_results(
        with_return_issues(result, contract_issues),
        length_exception_result,
    )


def handle_common_return_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    expected_function_name = state.call_stack[-1].function_name if state.call_stack else None
    return_value = state.pop() if state.stack else None
    contract_issues = collect_return_postcondition_issues(
        state,
        return_value,
        getattr(ctx, "config", None),
        expected_function_name=expected_function_name,
    )
    frame = state.pop_call()
    if state.call_stack:
        state.local_vars = state.call_stack[-1].local_vars
    if frame is not None:
        return _handle_return_value_with_frame(
            frame,
            instr,
            state,
            ctx,
            return_value,
            contract_issues,
        )
    if contract_issues:
        return OpcodeResult(new_states=[], issues=contract_issues, terminal=True)
    return OpcodeResult.terminate()
