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

"""Nested-frame entry orchestration for interprocedural calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.binding import (
    binding_type_error_result,
    validate_python_function_binding,
)
from pysymex._internal.execution.calls.interprocedural.activation import (
    activate_callee_bytecode,
    push_interprocedural_frame,
)
from pysymex._internal.execution.calls.interprocedural.bytecode import (
    CalleeBytecode,
    load_callee_bytecode,
)
from pysymex._internal.execution.calls.interprocedural.contracts import (
    ContractEntryFrame,
    check_runtime_contract_entry,
    prepare_contract_entry_frame,
)
from pysymex._internal.execution.calls.interprocedural.frames import (
    build_interprocedural_call_frame,
)
from pysymex._internal.execution.calls.interprocedural.locals.defaults import (
    CalleeDefaultBindings,
    prepare_callee_default_bindings,
)
from pysymex._internal.execution.calls.interprocedural.locals.locals import build_callee_local_vars
from pysymex._internal.execution.calls.interprocedural.partials import expand_partial_call
from pysymex._internal.execution.calls.interprocedural.protocols import (
    maybe_create_protocol_callable,
)
from pysymex._internal.execution.calls.interprocedural.recursion import (
    recursive_call_requires_summary,
)
from pysymex._internal.execution.calls.interprocedural.signature import (
    CalleeSignature,
    callee_signature,
)
from pysymex._internal.execution.calls.interprocedural.summaries import (
    build_interprocedural_summary,
)
from pysymex._internal.execution.calls.interprocedural.targets import (
    InterproceduralTarget,
    resolve_interprocedural_target,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _caller_instruction_and_offset(
    state: VMState,
    ctx: OpcodeDispatcher,
) -> tuple[dis.Instruction | None, int]:
    """Return the current caller instruction and offset used for recursion/binding errors."""
    caller_instruction = ctx.get_instruction(state.pc)
    caller_offset = caller_instruction.offset if caller_instruction is not None else state.pc
    return caller_instruction, caller_offset


def _perform_expanded_partial_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    *,
    is_init: bool,
    init_instance: StackValue | None,
    protocol_method: str | None,
    resume_pc: int | None,
    protocol_retained_operand: StackValue | None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...],
    caller_instructions_override: list[object] | None,
    caller_offset_override: int | None,
) -> OpcodeResult | None:
    """Inline an expanded ``functools.partial`` target when present."""
    partial_call = expand_partial_call(func_obj, args, kwargs)
    if partial_call is None:
        return None
    return perform_interprocedural_call_impl(
        state,
        ctx,
        partial_call.func_obj,
        partial_call.args,
        partial_call.kwargs,
        is_init=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        caller_instructions_override=caller_instructions_override,
        caller_offset_override=caller_offset_override,
    )


def _prepare_defaults_or_binding_error(
    state: VMState,
    ctx: OpcodeDispatcher,
    target: InterproceduralTarget,
    signature: CalleeSignature,
    caller_offset: int,
) -> tuple[VMState, CalleeDefaultBindings | None, OpcodeResult | None]:
    """Prepare default bindings and return a binding-error result when arguments fail."""
    defaults = prepare_callee_default_bindings(
        state,
        target.func_obj,
        target.func_code,
        signature.pos_arg_names,
        signature.kwonly_arg_names,
        signature.arg_count,
    )
    state = defaults.state
    binding_error = validate_python_function_binding(
        target.func_name,
        target.func_code,
        target.args,
        target.kwargs,
        defaults.positional_defaults,
        defaults.keyword_defaults,
    )
    if binding_error is None:
        return state, defaults, None
    return state, None, binding_type_error_result(state, ctx, caller_offset, binding_error.message)


def _build_callee_locals_and_contract_entry(
    state: VMState,
    ctx: OpcodeDispatcher,
    target: InterproceduralTarget,
    signature: CalleeSignature,
    defaults: CalleeDefaultBindings,
) -> tuple[
    VMState,
    dict[str, StackValue],
    object | None,
    Callable[..., object] | None,
    ContractEntryFrame,
]:
    """Build callee locals and capture contract-entry metadata."""
    state, new_locals = build_callee_local_vars(
        state,
        target.func_obj,
        target.func_code,
        target.func_name,
        target.symbolic_closure,
        target.args,
        target.kwargs,
        signature.pos_arg_names,
        signature.kwonly_arg_names,
        signature.arg_count,
        defaults.positional_defaults,
        defaults.keyword_defaults,
    )
    config = getattr(ctx, "config", None)
    contract_callable = target.func_obj if callable(target.func_obj) else None
    contract_entry = prepare_contract_entry_frame(
        config,
        contract_callable,
        target.func_code,
        new_locals,
        state,
    )
    return state, new_locals, config, contract_callable, contract_entry


def _push_and_activate_callee_frame(
    state: VMState,
    ctx: OpcodeDispatcher,
    target: InterproceduralTarget,
    signature: CalleeSignature,
    callee_bytecode: CalleeBytecode,
    new_locals: dict[str, StackValue],
    contract_entry: ContractEntryFrame,
    config: object | None,
    contract_callable: Callable[..., object] | None,
    caller_instruction: dis.Instruction | None,
    *,
    is_init: bool,
    init_instance: StackValue | None,
    protocol_method: str | None,
    resume_pc: int | None,
    protocol_retained_operand: StackValue | None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...],
    caller_instructions_override: list[object] | None,
    caller_offset_override: int | None,
) -> tuple[VMState | None, list[Issue]]:
    """Push the interprocedural frame, apply contracts, and activate callee bytecode."""
    builder = build_interprocedural_summary(
        ctx,
        target,
        signature.pos_arg_names,
        signature.kwonly_arg_names,
    )
    frame = build_interprocedural_call_frame(
        state=state,
        target=target,
        caller_instruction=caller_instruction,
        caller_instructions=ctx.instructions,
        summary_builder=builder,
        is_init=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        has_contract_frame=contract_entry.owns_frame,
        pos_arg_names=signature.pos_arg_names,
        caller_instructions_override=caller_instructions_override,
        caller_offset_override=caller_offset_override,
    )
    state = push_interprocedural_frame(state=state, frame=frame, new_locals=new_locals)
    checked_state, contract_issues = check_runtime_contract_entry(
        state,
        config,
        contract_callable,
        target.args,
        target.kwargs,
        contract_entry.frame,
    )
    if checked_state is None:
        return None, contract_issues
    state = activate_callee_bytecode(
        state=checked_state,
        ctx=ctx,
        new_locals=new_locals,
        callee_instructions=callee_bytecode.instructions,
        exception_entries=callee_bytecode.exception_entries,
    )
    return state, contract_issues


def perform_interprocedural_call_impl(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
    is_init: bool = False,
    init_instance: StackValue | None = None,
    protocol_method: str | None = None,
    resume_pc: int | None = None,
    protocol_retained_operand: StackValue | None = None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = (),
    caller_instructions_override: list[object] | None = None,
    caller_offset_override: int | None = None,
) -> OpcodeResult | None:
    """Push a nested frame for a user-defined callable when inlining is possible."""
    kwargs = kwargs or {}
    partial_result = _perform_expanded_partial_call(
        state,
        ctx,
        func_obj,
        args,
        kwargs,
        is_init=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        caller_instructions_override=caller_instructions_override,
        caller_offset_override=caller_offset_override,
    )
    if partial_result is not None:
        return partial_result

    target = resolve_interprocedural_target(func_obj, args, kwargs)
    if target is None:
        return None
    caller_instruction, caller_offset = _caller_instruction_and_offset(state, ctx)
    if recursive_call_requires_summary(state, target, caller_offset):
        return None

    special_call = maybe_create_protocol_callable(
        state,
        target.func_obj,
        target.args,
        target.kwargs,
        target.func_code,
        protocol_method=protocol_method,
    )
    if special_call is not None:
        return special_call

    callee_bytecode = load_callee_bytecode(target.func_code)
    if callee_bytecode is None:
        return None
    signature = callee_signature(target.func_code)
    state, defaults, binding_result = _prepare_defaults_or_binding_error(
        state,
        ctx,
        target,
        signature,
        caller_offset,
    )
    if binding_result is not None:
        return binding_result
    if defaults is None:
        return None

    state, new_locals, config, contract_callable, contract_entry = (
        _build_callee_locals_and_contract_entry(state, ctx, target, signature, defaults)
    )
    callee_state, contract_issues = _push_and_activate_callee_frame(
        state,
        ctx,
        target,
        signature,
        callee_bytecode,
        new_locals,
        contract_entry,
        config,
        contract_callable,
        caller_instruction,
        is_init=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        caller_instructions_override=caller_instructions_override,
        caller_offset_override=caller_offset_override,
    )
    if callee_state is None:
        return OpcodeResult(new_states=[], issues=contract_issues, terminal=True)
    return OpcodeResult(new_states=[callee_state], issues=contract_issues)


def perform_interprocedural_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Public internal wrapper for opcode helpers that dispatch user callables."""
    return perform_interprocedural_call_impl(state, ctx, func_obj, args, kwargs)
