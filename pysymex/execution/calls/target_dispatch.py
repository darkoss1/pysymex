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

"""Dispatch resolved call targets after opcode stack lowering."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.runtime.summaries import FunctionSummary, instantiate_summary
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.class_calls import (
    try_modeled_class_call,
    try_modeled_object_allocation,
)
from pysymex.execution.calls.helpers import (
    CrossFunctionProtocol,
    UNMODELED_CALL_ABSTRACTION,
    UNSUPPORTED_CALL_PROTOCOL,
    as_stack_value,
    create_unmodeled_call_havoc,
    to_z3_expr,
)
from pysymex.execution.calls.interprocedural import perform_interprocedural_call_impl
from pysymex.execution.calls.model_dispatch import (
    MAX_SUMMARY_CACHE_ARGS,
    MAX_SUMMARY_CACHE_CONSTRAINTS,
    apply_model,
    handle_definite_non_callable_call,
    path_is_sat,
)
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


def dispatch_expanded_call_target(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Dispatch an already expanded call target after opcode-specific stack lowering."""
    non_callable_result = handle_definite_non_callable_call(instr, state, ctx, func_obj)
    if non_callable_result is not None:
        return non_callable_result

    if isinstance(func_obj, SymbolicValue):
        is_none = func_obj.is_none
        non_none = z3.Not(is_none)
        can_raise = path_is_sat([*state.path_constraints, is_none])
        can_succeed = path_is_sat([*state.path_constraints, non_none])
        handler_pc = ctx.find_exception_handler(instr.offset)

        if can_raise and not can_succeed:
            error_state = state.fork().add_constraint(is_none)
            non_callable_result = handle_definite_non_callable_call(instr, error_state, ctx, None)
            if non_callable_result is not None:
                return non_callable_result
            return OpcodeResult.terminate()

        if can_raise and handler_pc is not None:
            error_result = handle_definite_non_callable_call(
                instr, state.fork().add_constraint(is_none), ctx, None
            )
            normal_state = state.fork().add_constraint(non_none)
            normal_result = dispatch_resolved_call(instr, normal_state, ctx, func_obj, args, kwargs)
            error_states = error_result.new_states if error_result is not None else []
            error_issues = error_result.issues if error_result is not None else []
            if normal_result.new_states:
                return OpcodeResult.branch(
                    [*normal_result.new_states, *error_states],
                    [*normal_result.issues, *error_issues],
                    normal_result.degraded_passes,
                    normal_result.fallback_events,
                )
            return OpcodeResult.branch(
                error_states,
                [*normal_result.issues, *error_issues],
                normal_result.degraded_passes,
                normal_result.fallback_events,
            )

        if can_raise:
            state = state.add_constraint(non_none)

    return dispatch_resolved_call(instr, state, ctx, func_obj, args, kwargs)


def dispatch_resolved_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Apply models, summaries, interprocedural calls, or havoc for one resolved target."""
    from pysymex.execution.opcodes.common.coroutines import try_dispatch_coroutine_call

    coroutine_result = try_dispatch_coroutine_call(state, func_obj, args, kwargs, ctx, instr)
    if coroutine_result is not None:
        return coroutine_result

    context_manager_result = _dispatch_context_manager_call(
        instr, state, ctx, func_obj, args, kwargs
    )
    if context_manager_result is not None:
        return context_manager_result

    exit_stack_result = _dispatch_exit_stack_call(instr, state, ctx, func_obj, args, kwargs)
    if exit_stack_result is not None:
        return exit_stack_result

    from pysymex.models.stdlib.contextlib.stubs import apply_supported_suppress_call

    suppress_result = apply_supported_suppress_call(func_obj, list(args), dict(kwargs))
    if suppress_result is not None:
        state = state.push(cast("StackValue", suppress_result)).advance_pc()
        return OpcodeResult.continue_with(state)
    from pysymex.models.stdlib.functools.core import apply_transparent_decorator_call

    decorator_result = apply_transparent_decorator_call(func_obj, list(args), dict(kwargs))
    if decorator_result is not None:
        state = state.push(cast("StackValue", decorator_result)).advance_pc()
        return OpcodeResult.continue_with(state)

    from pysymex.models.stdlib.data.operator import AttrGetterCallable, ItemGetterCallable

    if isinstance(func_obj, ItemGetterCallable) and len(args) == 1 and not kwargs:
        from pysymex.execution.opcodes.common.collections.subscript import (
            handle_common_binary_subscr,
        )

        subscript_state = state.push(args[0]).push(func_obj.index)
        return handle_common_binary_subscr(
            instr,
            subscript_state,
            ctx,
            report_mixed_list_error=True,
        )

    if isinstance(func_obj, AttrGetterCallable) and len(args) == 1 and not kwargs:
        from pysymex.execution.opcodes.common.functions.attribute.load import (
            handle_common_load_method,
        )

        load_instr = instr._replace(opname="LOAD_ATTR", arg=0, argval=func_obj.attr_name)
        return handle_common_load_method(load_instr, state.push(args[0]), ctx)

    from pysymex.execution.calls.object_attribute_descriptors import (
        try_object_attribute_descriptor_call,
    )

    object_attribute_result = try_object_attribute_descriptor_call(
        instr,
        state,
        ctx,
        func_obj,
        args,
        kwargs,
    )
    if object_attribute_result is not None:
        return object_attribute_result

    from pysymex.models.builtins.core.conversions.numeric import SliceIndicesCallable

    if isinstance(func_obj, SliceIndicesCallable) and len(args) == 1 and not kwargs:
        length: int | z3.ArithRef | None = None
        if isinstance(args[0], int) and not isinstance(args[0], bool):
            length = args[0]
        elif (
            isinstance(args[0], SymbolicValue)
            and args[0].affinity_type == "int"
            and args[0].name.startswith("len_")
        ):
            length = args[0].z3_int
        if isinstance(length, int) and length < 0:
            length = None
        if length is not None:
            state = state.push(as_stack_value(func_obj.for_nonnegative_length(length)))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

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
        from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

        call_method = lookup_modeled_method(func_obj, "__call__")
        if call_method is not None:
            call_result = perform_interprocedural_call_impl(
                state, ctx, call_method, [func_obj, *args], kwargs
            )
            if call_result is not None:
                return call_result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_CALL_PROTOCOL],
                fallback_events=[_unsupported_call_protocol_event(state=state)],
                terminal=True,
            )

    call_name = _call_target_name(func_obj)

    if ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache"):
        cross_function = cast("CrossFunctionProtocol", ctx.cross_function)
        cache = cross_function.function_summary_cache
        path_constraints_snapshot = list(state.path_constraints)
        summary = None
        if (
            len(path_constraints_snapshot) <= MAX_SUMMARY_CACHE_CONSTRAINTS
            and len(args) <= MAX_SUMMARY_CACHE_ARGS
        ):
            summary = cache.get(call_name, args, path_constraints_snapshot)
        if isinstance(summary, FunctionSummary):
            z3_args: list[z3.ExprRef] = []
            for arg in args:
                expr = to_z3_expr(arg)
                if expr is None:
                    z3_args = []
                    break
                z3_args.append(expr)

            z3_kwargs: dict[str, z3.ExprRef] = {}
            if z3_args:
                for key, value in kwargs.items():
                    expr = to_z3_expr(value)
                    if expr is None:
                        z3_kwargs = {}
                        z3_args = []
                        break
                    z3_kwargs[key] = expr

            if z3_args:
                pre, post, ret_val = instantiate_summary(summary, z3_args, z3_kwargs)
                state = state.add_constraint(pre)
                state = state.add_constraint(post)
                if ret_val is None:
                    state = state.push(SymbolicNone())
                else:
                    state = state.push(SymbolicValue.from_z3(ret_val))
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)

    result = perform_interprocedural_call_impl(state, ctx, func_obj, args, kwargs)
    if result:
        return result

    fallback_event = _unmodeled_call_havoc_event(state=state, call_name=call_name)
    ret, tc = create_unmodeled_call_havoc(state, func_obj)
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()

    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNMODELED_CALL_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def _dispatch_context_manager_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply trusted ``contextlib.contextmanager`` factory and normal exit calls."""
    from pysymex.models.stdlib.contextlib.managers import ContextManager, ContextManagerFactory

    if isinstance(func_obj, ContextManagerFactory):
        manager = func_obj(*args, **kwargs)
        state = state.push(as_stack_value(manager)).advance_pc()
        return OpcodeResult.continue_with(state)

    receiver = getattr(func_obj, "__self__", None)
    if not isinstance(receiver, ContextManager):
        return None

    method_name = getattr(func_obj, "__name__", "")
    if method_name != "__exit__":
        return None

    if not _context_manager_normal_exit(args):
        from pysymex.execution.opcodes.common.control_fallbacks import (
            UNSUPPORTED_GENERATOR,
            unsupported_generator_event,
        )

        fallback_event = unsupported_generator_event(
            state=state,
            reason="contextlib.contextmanager exception throw is not modeled precisely",
        )
        state = state.push(False).advance_pc()
        return OpcodeResult.continue_with(
            state,
            degraded_passes=[UNSUPPORTED_GENERATOR],
            fallback_events=[fallback_event],
        )

    generator = receiver.generator
    if generator is None:
        state = state.push(SymbolicNone()).advance_pc()
        return OpcodeResult.continue_with(state)

    return apply_model(state, next, [cast("StackValue", generator), None], {}, ctx, instr)


def _context_manager_normal_exit(args: list[StackValue]) -> bool:
    """Return whether ``__exit__`` arguments represent a no-exception with exit."""
    return all(arg is None or isinstance(arg, SymbolicNone) for arg in args)


def _dispatch_exit_stack_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply trusted ``ExitStack`` methods without analyzing model internals as target code."""
    if kwargs:
        return None

    from pysymex.models.stdlib.contextlib.stacks import ExitStackModel

    receiver = getattr(func_obj, "__self__", None)
    if not isinstance(receiver, ExitStackModel):
        return None

    method_name = getattr(func_obj, "__name__", "")
    if method_name == "__exit__":
        exit_args = list(args)
        while len(exit_args) < 3:
            exit_args.append(None)
        raw_exc_type = exit_args[0]
        raw_exc_val = exit_args[1]
        exc_type = (
            raw_exc_type
            if isinstance(raw_exc_type, type) and issubclass(raw_exc_type, BaseException)
            else None
        )
        exc_val = raw_exc_val if isinstance(raw_exc_val, BaseException) else None
        result = receiver.__exit__(exc_type, exc_val, None)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if method_name != "enter_context" or len(args) != 1:
        return None

    manager = args[0]
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    exit_method = lookup_modeled_method(manager, "__exit__")
    if exit_method is not None:
        receiver.register_exit_callback(exit_method)

    enter_method = lookup_modeled_method(manager, "__enter__")
    if enter_method is not None:
        return perform_interprocedural_call_impl(
            state,
            ctx,
            enter_method,
            [],
            {},
            protocol_method="__enter__",
        )

    manager_obj = manager.value if isinstance(manager, SymbolicValue) else manager
    enter = getattr(manager_obj, "__enter__", None)
    exit_ = getattr(manager_obj, "__exit__", None)
    if callable(enter) and callable(exit_):
        receiver.register_exit_callback(exit_)
        state = state.push(as_stack_value(enter()))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    return None


def _call_target_name(func_obj: object) -> str:
    """Return the best stable call target name available for fallback events."""
    for attr_name in ("model_name", "__qualname__", "__name__", "_func_name", "name"):
        candidate = getattr(func_obj, attr_name, None)
        if isinstance(candidate, str) and candidate:
            return candidate
    return type(func_obj).__name__


def _unsupported_call_protocol_event(*, state: VMState) -> FallbackEvent:
    """Build the fallback event for unsupported symbolic ``__call__`` protocol paths."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_CALL_PROTOCOL,
        owner="execution.calls",
        reason="symbolic __call__ target could not be modeled or entered interprocedurally",
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.LOW,
        false_negative_risk=RiskLevel.HIGH,
    )


def _unmodeled_call_havoc_event(*, state: VMState, call_name: str) -> FallbackEvent:
    """Build the fallback event for unmodeled call havoc."""
    return FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label=UNMODELED_CALL_ABSTRACTION,
        owner="execution.calls",
        reason=f"unmodeled call target {call_name!r} abstracted with havoc",
        pc=state.pc,
        soundness=SoundnessTag.PRECISION_LOSS,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )
