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

"""Context-manager opcode flow for ``with`` and ``async with`` statements."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.classes.types import SymbolicMethod
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.fallbacks import (
    UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL,
    flag_unsupported_context_manager,
)
from pysymex._internal.execution.opcodes.common.exceptions.classes import raised_exception_class
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.models.stdlib.contextlib.stubs import Suppress

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_with_except_start(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    exit_meth = None
    for item in reversed(state.stack):
        if isinstance(item, SymbolicMethod) and item.name == "__exit__":
            exit_meth = item
            break
        if callable(item) or hasattr(item, "__self__") or hasattr(item, "__func__"):
            method = getattr(item, "method", None)
            method_name = getattr(method, "name", getattr(item, "__name__", ""))
            if method_name == "__exit__":
                exit_meth = item
                break

    if exit_meth is not None:
        exc = _with_exception_value(state)
        exc_type = _with_exception_type(exc)
        receiver = getattr(exit_meth, "__self__", None)
        if isinstance(receiver, Suppress):
            state = state.push(receiver.suppresses(exc_type))
            return OpcodeResult.continue_with(state.advance_pc())
        from pysymex._internal.execution.calls.interprocedural.entry import (
            perform_interprocedural_call_impl,
        )

        res = perform_interprocedural_call_impl(
            state,
            ctx,
            exit_meth,
            [exc_type, exc, None],
            protocol_method="__exit__",
        )
        if res is not None:
            return res

    result, constraint = SymbolicValue.symbolic(f"with_exit_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _with_exception_value(state: VMState) -> StackValue:
    """Return the exception value consumed by ``WITH_EXCEPT_START``."""
    active_exception = state.active_exception
    if active_exception is not None and _is_exception_stack_value(active_exception):
        return active_exception
    for candidate in reversed(state.stack):
        if _is_exception_stack_value(candidate):
            return candidate
    if active_exception is not None:
        return active_exception
    if len(state.stack) >= 3:
        return state.peek(2)
    return SymbolicValue.symbolic(f"exc_{state.pc}")[0]


def _with_exception_type(exc: object) -> StackValue:
    """Return the CPython ``exc_type`` argument for a context-manager exit call."""
    raised_type = raised_exception_class(exc)
    if raised_type is not None:
        return cast("StackValue", raised_type)
    payload = _symbolic_exception_payload(exc)
    if payload is not None:
        return cast("StackValue", payload.exc_type)
    return cast("StackValue", type(exc))


def _is_exception_stack_value(value: object) -> bool:
    """Return whether *value* can model a handled exception."""
    return (
        raised_exception_class(value) is not None or _symbolic_exception_payload(value) is not None
    )


def _symbolic_exception_payload(value: object) -> SymbolicException | None:
    """Return the symbolic exception payload from a direct or modeled value."""
    if isinstance(value, SymbolicException):
        return value
    modeled_value = getattr(value, "_modeled_object", None)
    return modeled_value if isinstance(modeled_value, SymbolicException) else None


def handle_common_before_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for with statement."""
    ExceptionFlow.require_depth(state, instr, 1, "BEFORE_WITH")
    mgr = state.pop()

    if isinstance(mgr, SymbolicValue):
        from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

        enter_meth = lookup_modeled_method(mgr, "__enter__")
        exit_meth = lookup_modeled_method(mgr, "__exit__")
        if enter_meth is not None or exit_meth is not None:
            if enter_meth is None or exit_meth is None:
                return OpcodeResult(
                    new_states=[],
                    issues=[],
                    degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
                    fallback_events=[
                        flag_unsupported_context_manager(
                            state=state,
                            reason="modeled context manager is missing __enter__ or __exit__",
                        ),
                    ],
                    terminal=True,
                )
            state = state.push(cast("StackValue", exit_meth))
            from pysymex._internal.execution.calls.interprocedural.entry import (
                perform_interprocedural_call_impl,
            )

            result = perform_interprocedural_call_impl(
                state,
                ctx,
                enter_meth,
                [],
                {},
                protocol_method="__enter__",
            )
            if result is not None:
                return result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
                fallback_events=[
                    flag_unsupported_context_manager(
                        state=state,
                        reason="modeled context manager __enter__ could not be entered",
                    ),
                ],
                terminal=True,
            )

    mgr_obj = mgr.value if isinstance(mgr, SymbolicValue) else mgr
    context_manager_result = _enter_contextlib_generator_manager(instr, state, ctx, mgr_obj)
    if context_manager_result is not None:
        return context_manager_result

    if isinstance(mgr_obj, Suppress):
        state = state.push(cast("StackValue", mgr_obj.__exit__)).push(cast("StackValue", mgr_obj))
        return OpcodeResult.continue_with(state.advance_pc())
    enter_meth = getattr(mgr_obj, "__enter__", None)
    exit_meth = getattr(mgr_obj, "__exit__", None)

    if enter_meth is not None and exit_meth is not None:
        state = state.push(exit_meth)
        from pysymex._internal.execution.calls.interprocedural.entry import (
            perform_interprocedural_call,
        )

        res = perform_interprocedural_call(state, ctx, enter_meth, [])
        if res is not None:
            return res
        state.pop()

    exit_val, c1 = SymbolicValue.symbolic(f"exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"enter_{state.pc}")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_before_async_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for async with statement."""
    ExceptionFlow.require_depth(state, instr, 1, "BEFORE_ASYNC_WITH")
    mgr = state.pop()
    if isinstance(mgr, SymbolicValue):
        from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

        enter_meth = lookup_modeled_method(mgr, "__aenter__")
        exit_meth = lookup_modeled_method(mgr, "__aexit__")
        if enter_meth is not None or exit_meth is not None:
            if enter_meth is None or exit_meth is None:
                return _unsupported_async_with(
                    state,
                    "modeled async context manager is missing __aenter__ or __aexit__",
                    terminal=True,
                )
            state = state.push(cast("StackValue", exit_meth))
            from pysymex._internal.execution.calls.interprocedural.entry import (
                perform_interprocedural_call_impl,
            )

            result = perform_interprocedural_call_impl(
                state,
                ctx,
                enter_meth,
                [],
                {},
                protocol_method="__aenter__",
            )
            if result is not None:
                return result
            return _unsupported_async_with(
                state,
                "modeled async context manager __aenter__ could not be entered",
                terminal=True,
            )

    exit_val, c1 = SymbolicValue.symbolic(f"async_exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"async_enter_{state.pc}")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    fallback_event = flag_unsupported_context_manager(
        state=state,
        reason="async context manager protocol could not be modeled precisely",
    )
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
        fallback_events=[fallback_event],
    )


def _unsupported_async_with(
    state: VMState,
    reason: str,
    *,
    terminal: bool,
) -> OpcodeResult:
    """Return an explicit unsupported async context-manager protocol result."""
    fallback_event = flag_unsupported_context_manager(state=state, reason=reason)
    return OpcodeResult(
        new_states=[] if terminal else [state],
        issues=[],
        degraded_passes=[UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL],
        fallback_events=[fallback_event],
        terminal=terminal,
    )


def handle_common_setup_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``SETUP_WITH``: pop manager and push symbolic enter/exit callables.

    CPython stack effect: pops the context manager, pushes ``__exit__`` then ``__enter__``
    results with feasibility literals. Modern ``before/with`` lowering lives in this module.

    Limitations:
        Does not model real context-manager protocol dispatch or async variants.
    """
    ExceptionFlow.require_depth(state, instr, 1, "SETUP_WITH")
    state.pop()

    exit_val, tc1 = SymbolicValue.symbolic(f"exit_{state.pc}")
    enter_val, tc2 = SymbolicValue.symbolic(f"enter_{state.pc}")

    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(tc1)
    state = state.add_constraint(tc2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _enter_contextlib_generator_manager(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    manager: object,
) -> OpcodeResult | None:
    """Enter a modeled ``contextlib.contextmanager`` through VM generator semantics."""
    from pysymex._internal.core.types.containers.generators import ModeledGenerator
    from pysymex._internal.execution.calls.model.dispatch import apply_model
    from pysymex._internal.models.stdlib.contextlib.managers import ContextManager

    if not isinstance(manager, ContextManager):
        return None

    name = str(
        getattr(manager.function, "__name__", None)
        or getattr(manager.function, "_func_name", None)
        or "contextmanager",
    )
    generator = ModeledGenerator(
        name,
        manager.function,
        cast("tuple[StackValue, ...]", manager.args),
        tuple((key, cast("StackValue", value)) for key, value in manager.kwargs.items()),
    )
    manager.bind_modeled_generator(generator)

    state = state.push(cast("StackValue", manager.__exit__))
    return apply_model(state, next, [cast("StackValue", generator)], {}, ctx, instr)
