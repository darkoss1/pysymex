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
forward control flow (see :mod:`pysymex.execution.opcodes.common.control.feasibility`).
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import z3

from pysymex.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.construction_fallbacks import (
    construction_return_fallback_events,
)
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    protocol_return_fallback_events,
)
from pysymex.execution.opcodes.common.control.protocol.returns import (
    normalize_truth_protocol_return,
)
from pysymex.execution.opcodes.common.control.return_state import (
    apply_argument_alias_updates,
    collect_return_postcondition_issues,
    restore_caller_stack,
)

_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12
_DISCARDED_MUTATION_RETURNS = {
    "__setitem__",
    "__delitem__",
    "__setattr__",
    "__delattr__",
    "__descriptor_set__",
    "__descriptor_delete__",
}


@runtime_checkable
class _SummaryCacheProtocol(Protocol):
    """Cross-function summary cache surface used on return paths."""

    def put(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
        summary: object,
    ) -> None:
        """Store a return summary keyed by function name, args, and path constraints."""
        ...


@runtime_checkable
class _CrossFunctionProtocol(Protocol):
    function_summary_cache: _SummaryCacheProtocol


def _combine_return_results(primary: OpcodeResult, secondary: OpcodeResult | None) -> OpcodeResult:
    """Merge an independently routed return-contract exception branch."""
    if secondary is None:
        return primary
    degraded_passes = list(dict.fromkeys([*primary.degraded_passes, *secondary.degraded_passes]))
    return OpcodeResult(
        new_states=[*primary.new_states, *secondary.new_states],
        issues=[*primary.issues, *secondary.issues],
        degraded_passes=degraded_passes,
        fallback_events=[*primary.fallback_events, *secondary.fallback_events],
        terminal=primary.terminal and secondary.terminal,
    )


def _with_return_issues(result: OpcodeResult, issues: list[Issue]) -> OpcodeResult:
    """Attach contract-return issues without changing successor control flow."""
    if not issues:
        return result
    return OpcodeResult(
        new_states=result.new_states,
        issues=[*issues, *result.issues],
        degraded_passes=result.degraded_passes,
        fallback_events=result.fallback_events,
        terminal=result.terminal,
    )


if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _degraded_protocol_return_result(state: VMState, degraded_pass: str) -> OpcodeResult:
    """Return a terminal protocol-degradation result with specific event metadata."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[degraded_pass],
        fallback_events=[
            *construction_return_fallback_events(
                state=state,
                degraded_pass=degraded_pass,
            ),
            *protocol_return_fallback_events(
                state=state,
                degraded_pass=degraded_pass,
            ),
        ],
        terminal=True,
    )


def handle_common_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a constant with shared interprocedural and protocol handling."""
    return_value = (
        SymbolicNone("return_None")
        if instr.argval is None
        else SymbolicValue.from_const(instr.argval)
    )
    contract_issues = collect_return_postcondition_issues(
        state, return_value, getattr(ctx, "config", None)
    )

    frame = state.pop_call()
    protocol_issue = None
    degraded_pass = None
    if frame is not None:
        return_value, protocol_issue, degraded_pass = normalize_truth_protocol_return(
            frame, return_value, state
        )
    if degraded_pass is not None:
        return _degraded_protocol_return_result(state, degraded_pass)
    if frame is None:
        if contract_issues or protocol_issue:
            return OpcodeResult(
                new_states=[],
                issues=[*contract_issues, *([protocol_issue] if protocol_issue else [])],
                terminal=True,
            )
        return OpcodeResult.terminate()
    from pysymex.execution.opcodes.common.coroutines import complete_coroutine_return
    from pysymex.execution.opcodes.common.generators import complete_generator_return

    coroutine_result = complete_coroutine_return(frame, state, ctx, return_value)
    if coroutine_result is not None:
        return coroutine_result
    generator_result = complete_generator_return(frame, state, ctx, return_value)
    if generator_result is not None:
        return generator_result

    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    state = state.set_pc(frame.return_pc)
    if frame.caller_instructions is not None:
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", caller_instructions)
        ctx.set_instructions(caller_instructions)
    if protocol_issue is None:
        from pysymex.execution.opcodes.common.control.lifecycle_returns import (
            continue_modeled_instance_initialization,
        )

        lifecycle_result = continue_modeled_instance_initialization(frame, return_value, state, ctx)
        if lifecycle_result is not None:
            return _with_return_issues(lifecycle_result, contract_issues)
    if protocol_issue is None:
        from pysymex.execution.opcodes.common.control.protocol.negotiation import (
            continue_deferred_protocol_call,
        )

        protocol_result = continue_deferred_protocol_call(frame, return_value, state, ctx)
        if protocol_result is not None:
            return _with_return_issues(protocol_result, contract_issues)
    if protocol_issue is None:
        from pysymex.execution.opcodes.common.control.protocol.continuations import (
            complete_retained_protocol_operation,
        )

        retained_result = complete_retained_protocol_operation(frame, return_value, state, ctx)
        if retained_result is not None:
            return _with_return_issues(retained_result, contract_issues)
    if frame.protocol_method in _DISCARDED_MUTATION_RETURNS:
        state.depth -= 1
        return _with_return_issues(OpcodeResult.continue_with(state), contract_issues)
    if frame.is_init_call:
        state = state.push(
            frame.init_instance
            if frame.init_instance is not None
            else SymbolicNone("missing_init_instance")
        )
    else:
        state = state.push(return_value)
    state.depth -= 1
    if protocol_issue:
        return _with_return_issues(
            OpcodeResult(new_states=[state], issues=[protocol_issue]), contract_issues
        )
    return _with_return_issues(OpcodeResult.continue_with(state), contract_issues)


def handle_common_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return_value = state.pop() if state.stack else None

    contract_issues = collect_return_postcondition_issues(
        state, return_value, getattr(ctx, "config", None)
    )

    frame = state.pop_call()
    protocol_issue = None
    degraded_pass = None
    length_exception_result: OpcodeResult | None = None
    if frame is not None:
        from pysymex.execution.opcodes.common.control.length_returns import (
            fork_feasible_negative_symbolic_length,
        )

        length_fork = fork_feasible_negative_symbolic_length(frame, return_value, state, ctx)
        if length_fork is not None:
            resumed_state, length_exception_result = length_fork
            if resumed_state is None:
                return length_exception_result
            state = resumed_state
        return_value, protocol_issue, degraded_pass = normalize_truth_protocol_return(
            frame, return_value, state
        )
    if degraded_pass is not None:
        return _degraded_protocol_return_result(state, degraded_pass)

    if state.call_stack:
        state.local_vars = state.call_stack[-1].local_vars

    if frame is not None and isinstance(frame.summary_builder, SummaryBuilder):
        builder = frame.summary_builder
        initial_args = builder.initial_args
        cross_function = ctx.cross_function

        if isinstance(cross_function, _CrossFunctionProtocol):
            constraints = list(state.path_constraints)
            summary_constraints = constraints
            summary = builder.build()

            param_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
            for i, arg in enumerate(initial_args):
                if isinstance(arg, SymbolicValue):
                    param_info = summary.parameters[i] if i < len(summary.parameters) else None
                    if param_info:
                        param_z3 = param_info.to_z3()
                        param_map.append((arg.z3_int, param_z3))

            canonical_return = return_value

            if isinstance(return_value, SymbolicValue):
                new_z3_int = z3.substitute(return_value.z3_int, *param_map)
                new_z3_bool = z3.substitute(return_value.z3_bool, *param_map)

                canonical_return = SymbolicValue(
                    _name=return_value.name,
                    z3_int=new_z3_int,
                    is_int=return_value.is_int,
                    z3_bool=new_z3_bool,
                    is_bool=return_value.is_bool,
                )

            summary.return_var = (
                canonical_return.z3_int if isinstance(canonical_return, SymbolicValue) else None
            )

            canonical_constraints: list[z3.BoolRef] = []
            for c in summary_constraints:
                canonical_constraints.append(z3.substitute(c, *param_map))

            summary.postconditions = canonical_constraints

            if (
                len(constraints) <= _MAX_SUMMARY_CACHE_CONSTRAINTS
                and len(initial_args) <= _MAX_SUMMARY_CACHE_ARGS
            ):
                cross_function.function_summary_cache.put(
                    getattr(builder.summary, "name", "unknown"),
                    initial_args,
                    constraints,
                    summary,
                )

    if frame is not None:
        from pysymex.execution.opcodes.common.coroutines import complete_coroutine_return
        from pysymex.execution.opcodes.common.generators import complete_generator_return

        coroutine_result = complete_coroutine_return(frame, state, ctx, return_value)
        if coroutine_result is not None:
            return coroutine_result
        generator_result = complete_generator_return(frame, state, ctx, return_value)
        if generator_result is not None:
            return generator_result
        caller_locals = apply_argument_alias_updates(state, frame)
        restore_caller_stack(state, frame)
        state.local_vars = caller_locals
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)

        if protocol_issue is None:
            from pysymex.execution.opcodes.common.control.lifecycle_returns import (
                continue_modeled_instance_initialization,
            )

            lifecycle_result = continue_modeled_instance_initialization(
                frame, return_value, state, ctx
            )
            if lifecycle_result is not None:
                return _combine_return_results(
                    _with_return_issues(lifecycle_result, contract_issues),
                    length_exception_result,
                )
        if protocol_issue is None:
            from pysymex.execution.opcodes.common.control.protocol.negotiation import (
                continue_deferred_protocol_call,
            )

            protocol_result = continue_deferred_protocol_call(frame, return_value, state, ctx)
            if protocol_result is not None:
                return _combine_return_results(
                    _with_return_issues(protocol_result, contract_issues),
                    length_exception_result,
                )
        if protocol_issue is None:
            from pysymex.execution.opcodes.common.control.protocol.continuations import (
                complete_retained_protocol_operation,
            )

            retained_result = complete_retained_protocol_operation(frame, return_value, state, ctx)
            if retained_result is not None:
                return _combine_return_results(
                    _with_return_issues(retained_result, contract_issues),
                    length_exception_result,
                )
        if frame.protocol_method in _DISCARDED_MUTATION_RETURNS:
            state.depth -= 1
            return _combine_return_results(
                _with_return_issues(OpcodeResult.continue_with(state), contract_issues),
                length_exception_result,
            )

        if not frame.is_init_call:
            if return_value is not None:
                state = state.push(return_value)
            else:
                state = state.push(SymbolicNone("return_None"))
        else:
            # For __init__ calls, we push the instance itself
            if frame.init_instance is not None:
                state = state.push(frame.init_instance)
            else:
                state = state.push(SymbolicNone("missing_init_instance"))

        state.depth -= 1
        if protocol_issue:
            return _combine_return_results(
                _with_return_issues(
                    OpcodeResult(new_states=[state], issues=[protocol_issue]),
                    contract_issues,
                ),
                length_exception_result,
            )
        return _combine_return_results(
            _with_return_issues(OpcodeResult.continue_with(state), contract_issues),
            length_exception_result,
        )
    if contract_issues or protocol_issue:
        return OpcodeResult(
            new_states=[],
            issues=[*contract_issues, *([protocol_issue] if protocol_issue else [])],
            terminal=True,
        )
    return OpcodeResult.terminate()
