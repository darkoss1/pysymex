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

"""Enter callee bytecode for user-defined functions, methods, and partials.

``perform_interprocedural_call_impl`` builds a :class:`~pysymex.core.state.CallFrame`,
binds arguments (including modeled methods and ``functools.partial``), enforces a call-depth
cap, and supports protocol suspension metadata for dunder continuations. Opcode handlers keep
CALL stack mechanics and delegate callee-entry policy here.

Limitations:
    Returns ``None`` when depth exceeds ``MAX_CALL_DEPTH`` or no code object is available;
    generic functions and some builtins are not inlined here.
"""

from __future__ import annotations

import inspect
from pysymex.logger import get_logger
import types
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from pysymex.analysis.detectors import Issue
from pysymex.analysis.runtime.summaries import SummaryBuilder
from pysymex.core.cache import get_exception_entries
from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.calls.binding import (
    binding_type_error_result,
    validate_python_function_binding,
)
from pysymex.execution.calls.helpers import as_stack_value
from pysymex.execution.calls.payload import (
    SymbolicFunctionPayload,
    function_payload,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.core.state.types import ProtocolCallCandidate
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

logger = get_logger(__name__)


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
) -> OpcodeResult | None:
    """Push a nested frame for a user-defined callable when inlining is possible.

    Args:
        state: Active VM state; call depth is checked before pushing a frame.
        ctx: Opcode dispatcher used for instruction lookup in the callee.
        func_obj: Function, method, ``SymbolicFunctionPayload``, or partial target.
        args: Positional stack values bound to the callee.
        kwargs: Keyword stack values (may be empty).
        is_init: When ``True``, treat as ``__init__`` (instance binding rules).
        init_instance: ``self`` for ``__init__`` calls.
        protocol_method: Suspended dunder name when resuming protocol dispatch.
        resume_pc: Caller PC to restore after a protocol callee returns.
        protocol_retained_operand: Operand preserved across the protocol call.
        protocol_fallbacks: Additional modeled candidates after ``NotImplemented``.

    Returns:
        ``OpcodeResult`` when a frame was pushed, else ``None`` to fall back to havoc/summary.

    Limitations:
        Depth capped at 10 nested interprocedural calls; no frame when code is missing.
    """
    MAX_CALL_DEPTH = 10
    if state.call_depth() >= MAX_CALL_DEPTH:
        return None

    from pysymex.core.state.types import CallFrame
    from pysymex.models.stdlib.functools.core import PartialModel

    kwargs = kwargs or {}
    if isinstance(func_obj, PartialModel):
        bound_args = [cast("StackValue", value) for value in func_obj.args]
        bound_kwargs = {name: cast("StackValue", value) for name, value in func_obj.kwargs.items()}
        bound_kwargs.update(kwargs)
        return perform_interprocedural_call_impl(
            state,
            ctx,
            func_obj.func,
            [*bound_args, *args],
            bound_kwargs,
            is_init=is_init,
            init_instance=init_instance,
            protocol_method=protocol_method,
            resume_pc=resume_pc,
            protocol_retained_operand=protocol_retained_operand,
            protocol_fallbacks=protocol_fallbacks,
        )

    try:
        from pysymex.models.objects import SymbolicMethod
    except ImportError:
        SymbolicMethod = None

    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
    symbolic_closure: tuple[object, ...] = ()

    if isinstance(func_obj, SymbolicFunctionPayload):
        func_code = func_obj.code
        symbolic_closure = func_obj.closure

    if isinstance(func_obj, types.MethodType) and func_obj.__self__ is not None:
        bound_self = as_stack_value(func_obj.__self__)
        args = [bound_self, *args]
        func_obj = func_obj.__func__
        func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)

    if SymbolicMethod is not None and isinstance(func_obj, SymbolicMethod):
        method_args, method_kwargs = func_obj.get_call_args(
            tuple(args),
            cast("dict[str, object]", dict(kwargs)),
        )
        args = cast("list[StackValue]", list(method_args))
        kwargs = cast("dict[str, StackValue]", method_kwargs)
        method_func = func_obj.func
        payload = function_payload(method_func)
        if payload is not None:
            func_code = payload.code
            symbolic_closure = payload.closure
        else:
            func_code = getattr(method_func, "__code__", None) or getattr(
                method_func, "_func_code", None
            )
        func_obj = method_func

    if func_code is None and hasattr(func_obj, "value"):
        inner = getattr(func_obj, "value", None)
        if inner is not None:
            func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner
    if func_code is None and hasattr(func_obj, "_modeled_object"):
        inner = getattr(func_obj, "_modeled_object", None)
        if inner is not None:
            payload = function_payload(inner)
            if payload is not None:
                func_code = payload.code
                symbolic_closure = payload.closure
            elif hasattr(inner, "co_code"):
                func_code = inner
            else:
                func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner

    func_name = getattr(func_obj, "__name__", None) or getattr(func_obj, "_func_name", "anonymous")

    if not isinstance(func_code, types.CodeType):
        return None

    if func_code.co_flags & inspect.CO_COROUTINE:
        from pysymex.execution.opcodes.common.coroutines import (
            COROUTINE_RESUME_PROTOCOL,
            create_coroutine_call,
        )

        if protocol_method != COROUTINE_RESUME_PROTOCOL:
            return create_coroutine_call(state, func_obj, args, kwargs)

    if func_code.co_flags & inspect.CO_GENERATOR and protocol_method != "__generator_resume__":
        from pysymex.execution.opcodes.common.generators import create_generator_call

        return create_generator_call(state, func_obj, args, kwargs)
    try:
        callee_instructions = cached_get_instructions(func_code)
    except (TypeError, ValueError):
        return None
    callee_exception_entries = list(get_exception_entries(func_code))

    arg_count = func_code.co_argcount
    pos_arg_names = func_code.co_varnames[:arg_count]
    kwonly_count = func_code.co_kwonlyargcount
    kwonly_arg_names = func_code.co_varnames[arg_count : arg_count + kwonly_count]
    defaults_obj = getattr(func_obj, "__defaults__", None)
    if defaults_obj is None and isinstance(func_obj, SymbolicFunctionPayload):
        defaults_obj = func_obj.defaults
    if isinstance(defaults_obj, tuple):
        defaults_tuple = cast("tuple[object, ...]", defaults_obj)
        defaults_count = len(defaults_tuple)
    else:
        defaults_tuple = ()
        defaults_count = 0
    default_offset = arg_count - defaults_count
    positional_defaults = {
        name: as_stack_value(defaults_tuple[index - default_offset])
        for index, name in enumerate(pos_arg_names)
        if index >= default_offset
    }
    kwdefaults_obj = getattr(func_obj, "__kwdefaults__", None)
    if kwdefaults_obj is None and isinstance(func_obj, SymbolicFunctionPayload):
        kwdefaults_obj = func_obj.kwdefaults
    if isinstance(kwdefaults_obj, dict):
        keyword_defaults = {
            name: as_stack_value(value)
            for name, value in cast("dict[str, object]", kwdefaults_obj).items()
        }
    elif isinstance(kwdefaults_obj, SymbolicDict):
        keyword_defaults = {}
        for name in kwonly_arg_names:
            found, value = kwdefaults_obj.concrete_value_for_key(name)
            if found:
                keyword_defaults[name] = as_stack_value(value)
    else:
        keyword_defaults = {}

    caller_instruction = ctx.get_instruction(state.pc)
    caller_offset = caller_instruction.offset if caller_instruction is not None else state.pc
    binding_error = validate_python_function_binding(
        str(func_name),
        func_code,
        args,
        kwargs,
        positional_defaults,
        keyword_defaults,
    )
    if binding_error is not None:
        return binding_type_error_result(state, ctx, caller_offset, binding_error.message)

    builder = None
    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        builder = SummaryBuilder(func_name)
        builder.set_qualname(func_name)
        builder.set_initial_args(cast("list[object]", list(args)))
        for name in (*pos_arg_names, *kwonly_arg_names):
            builder.add_parameter(name)

    new_locals: dict[str, StackValue] = {}

    try:
        closure = symbolic_closure or getattr(func_obj, "__closure__", None)
        freevars = list(getattr(func_code, "co_freevars", ()))
        if closure and freevars:
            from pysymex.core.types.containers.objects import SymbolicObject
            from pysymex.core.identity.addressing import next_address

            for fv_name, cell in zip(freevars, closure, strict=False):
                if isinstance(cell, SymbolicObject) and cell.name.startswith("cell_"):
                    new_locals[fv_name] = cell
                else:
                    from typing import Any

                    try:
                        content = cast(Any, cell).cell_contents
                    except ValueError:
                        content = SymbolicNone()
                    except AttributeError:
                        content = cell
                    addr = next_address()
                    state = state.store_heap(addr, cast("StackValue", content))
                    new_locals[fv_name] = SymbolicObject(
                        f"cell_{fv_name}", addr, get_int_val(addr), {addr}
                    )
    except (AttributeError, TypeError):
        logger.debug("Unable to copy closure cells for %s", func_name)

    for i, name in enumerate(pos_arg_names):
        if i < len(args):
            new_locals[name] = args[i]
        elif name in kwargs:
            new_locals[name] = kwargs[name]
        else:
            new_locals[name] = positional_defaults[name]

    for name in kwonly_arg_names:
        if name in kwargs:
            new_locals[name] = kwargs[name]
        else:
            new_locals[name] = keyword_defaults[name]

    trailing_arg_index = arg_count + kwonly_count
    if func_code.co_flags & 0x04:
        vararg_name = func_code.co_varnames[trailing_arg_index]
        extra_pos = args[arg_count:] if len(args) > arg_count else []

        vararg_items = cast("list[object]", list(extra_pos))
        vararg_list = SymbolicList.empty(vararg_name).extend(vararg_items)
        new_locals[vararg_name] = vararg_list
        trailing_arg_index += 1

    if func_code.co_flags & 0x08:
        kwarg_name = func_code.co_varnames[trailing_arg_index]
        unused_kwargs: dict[str, StackValue] = {
            k: v for k, v in kwargs.items() if k not in pos_arg_names and k not in kwonly_arg_names
        }
        new_locals[kwarg_name] = unused_kwargs

    config = getattr(ctx, "config", None)
    contract_frame: object | None = None
    contract_callable = func_obj if callable(func_obj) else None
    if (
        config
        and getattr(config, "enable_contract_verification", False)
        and contract_callable is not None
    ):
        from pysymex.contracts.decorators import get_function_contract
        from pysymex.contracts.invariants import has_invariant_exit_obligations
        from pysymex.contracts.types import EffectKind

        contract = get_function_contract(contract_callable)
        has_effect_obligation = bool(
            contract and (contract.assigns_declared or contract.effect_type is EffectKind.PURE)
        )
        has_postcondition_obligation = bool(
            contract
            and contract.postconditions
            and getattr(config, "check_contract_postconditions", True)
        )
        has_invariant_exit = bool(
            getattr(config, "check_contract_class_invariants", True)
            and has_invariant_exit_obligations(contract_callable)
        )
    else:
        has_effect_obligation = False
        has_postcondition_obligation = False
        has_invariant_exit = False

    if contract_callable is not None and (
        has_postcondition_obligation or has_effect_obligation or has_invariant_exit
    ):
        from pysymex.contracts.binding import runtime_contract_frame

        contract_frame = runtime_contract_frame(
            contract_callable,
            new_locals,
            state.memory,
            effect_start_index=len(state.write_events),
        )

    from pysymex.core.state.types import wrap_cow_dict

    frame = CallFrame(
        function_name=func_name,
        return_pc=state.pc + 1 if resume_pc is None else resume_pc,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_stack=tuple(state.stack),
        caller_instructions=cast("list[object]", list(ctx.instructions)),
        summary_builder=builder,
        is_init_call=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        argument_aliases=tuple(
            (str(name), args[index])
            for index, name in enumerate(pos_arg_names)
            if index < len(args)
        ),
        caller_offset=caller_instruction.offset if caller_instruction is not None else None,
    )

    # Update state to use NEW locals (callee)
    state.local_vars = wrap_cow_dict(new_locals)
    state = state.push_call(frame)

    contract_issues: list[Issue] = []
    if (
        config
        and getattr(config, "enable_contract_verification", False)
        and contract_callable is not None
    ):
        from pysymex.contracts.runtime.calls import inject_call_preconditions

        checked_state, contract_issues = inject_call_preconditions(
            state,
            contract_callable,
            args,
            kwargs,
            include_preconditions=getattr(config, "check_contract_preconditions", True),
        )
        if checked_state is None:
            return OpcodeResult(new_states=[], issues=contract_issues, terminal=True)
        state = checked_state
        if getattr(config, "check_contract_class_invariants", True):
            from pysymex.contracts.invariants import InvariantCheckPoint, check_class_invariants

            contract_issues.extend(
                check_class_invariants(
                    state,
                    contract_callable,
                    InvariantCheckPoint.ENTRY,
                )
            )
        if (
            getattr(config, "check_contract_postconditions", True)
            or has_effect_obligation
            or has_invariant_exit
        ):
            state.contract_frames.append(
                contract_frame
                if contract_frame is not None
                else cast("Callable[..., object]", func_obj)
            )

    state.local_vars = wrap_cow_dict(new_locals)
    state.current_instructions = cast("list[object]", list(callee_instructions))
    ctx.register_exception_entries(list(callee_instructions), callee_exception_entries)
    ctx.set_instructions(list(callee_instructions))
    state = state.set_pc(0)
    state.depth += 1

    return OpcodeResult(new_states=[state], issues=contract_issues)


def perform_interprocedural_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Public internal wrapper for opcode helpers that dispatch user callables."""
    return perform_interprocedural_call_impl(state, ctx, func_obj, args, kwargs)
