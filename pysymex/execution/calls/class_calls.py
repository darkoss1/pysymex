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

"""Dispatch ``CALL`` targets to modeled object allocation and class constructors.

Routes known modeled types (exceptions, containers, local classes) to summary or inline
constructors instead of generic symbolic calls. Falls back to normal call lowering when the
callee is not a registered model.

Limitations:
    Unregistered callables and incomplete class metadata return ``None`` for further handling.
"""

from __future__ import annotations

from collections.abc import Callable
import dis
import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.calls.construction_fallbacks import (
    CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON,
    METACLASS_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
    unsupported_construction_event,
)
from pysymex.execution.calls.contract_obligations import (
    has_enabled_runtime_contract_obligations,
)
from pysymex.execution.opcodes.common.functions.classes import (
    apply_straight_line_init_assignments,
    modeled_class_from_python_type,
    modeled_class_from_value,
    modeled_instance_value,
    register_class_body_methods,
)
from pysymex.execution.opcodes.common.functions.classes.stdlib_contracts import (
    concrete_named_tuple_fields,
    configure_concrete_named_tuple_class,
    named_tuple_call_error,
    try_literal_enum_constructor,
)
from pysymex.execution.calls.interprocedural import (
    perform_interprocedural_call_impl,
)
from pysymex.execution.calls.type_call import BoundTypeCall

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def try_modeled_object_allocation(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Allocate a known modeled class through ``object.__new__(cls)``."""
    if func_obj is not object.__new__ or len(args) != 1 or kwargs:
        return None
    target = args[0]
    from pysymex.models.objects import class_registry

    if isinstance(target, SymbolicValue):
        modeled_cls = modeled_class_from_value(target)
    elif isinstance(target, type):
        modeled_cls = modeled_class_from_python_type(target)
    else:
        return None

    if modeled_cls is None:
        return None
    instance = class_registry.create_instance(modeled_cls)
    state = state.push(modeled_instance_value(modeled_cls.name, instance, state.pc))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _apply_init_type_hints(modeled_cls: object, hints: object) -> None:
    """Apply registration-time init type-hint strings to modeled constructor parameters."""
    if not isinstance(hints, dict):
        return
    typed_hints = cast("dict[object, object]", hints)
    for param in getattr(modeled_cls, "init_params", []):
        param_name = getattr(param, "name", None)
        if isinstance(param_name, str) and param_name in typed_hints:
            setattr(param, "type_hint", str(typed_hints[param_name]).lower())


def _modeled_method_callable(method: object | None) -> Callable[..., object] | None:
    """Return the concrete callable carried by a modeled method, when present."""
    raw_func = getattr(method, "func", None)
    if callable(raw_func):
        return raw_func
    return None


def _dispatch_custom_metaclass_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    class_value: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    modeled_cls: object,
) -> OpcodeResult | None:
    """Enter a source-visible metaclass ``__call__`` before direct construction."""
    from pysymex.models.objects import SymbolicClass

    metaclass = getattr(modeled_cls, "metaclass", None)
    if not isinstance(metaclass, SymbolicClass):
        return None
    if metaclass.module == "builtins" and metaclass.name == "type":
        return None
    call_method = metaclass.lookup_method("__call__")
    if call_method is None:
        return None
    bind_to_class = getattr(call_method, "bind_to_class", None)
    if not callable(bind_to_class):
        return None
    bound_call = bind_to_class(cast("StackValue", class_value))
    result = perform_interprocedural_call_impl(
        state,
        ctx,
        bound_call,
        args,
        kwargs,
        protocol_method="metaclass.__call__",
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_CONSTRUCTION_PROTOCOL],
        fallback_events=[
            unsupported_construction_event(
                state=state,
                reason=METACLASS_CALL_UNAVAILABLE_REASON,
            )
        ],
        terminal=True,
    )


def try_modeled_class_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    *,
    bypass_metaclass: bool = False,
) -> OpcodeResult | None:
    """Try to handle a call via the unified modeled class registry.

    If ``func_obj`` matches a registered class in the
    :class:`ClassRegistry`, create a
    :class:`SymbolicInstance` and push it onto the stack.
    Returns None if not applicable.
    """
    if isinstance(func_obj, BoundTypeCall):
        type_call_args = list(args)
        if type_call_args and type_call_args[0] is func_obj.target:
            type_call_args = type_call_args[1:]
        return try_modeled_class_call(
            instr,
            state,
            ctx,
            func_obj.target,
            type_call_args,
            kwargs,
            bypass_metaclass=True,
        )

    try:
        from pysymex.models.objects import (
            SymbolicClass,
            class_registry,
            extract_init_params,
        )

        func_name = (
            getattr(func_obj, "_name", None)
            or getattr(func_obj, "name", None)
            or (func_obj.__name__ if isinstance(func_obj, type) else None)
        )
        if func_name is None:
            return None

            # Only handle real classes or SymbolicValues with affinity_type="type"
        if not isinstance(func_obj, type):
            if (
                not isinstance(func_obj, SymbolicValue)
                or getattr(func_obj, "affinity_type", None) != "type"
            ):
                return None

        class_name = func_name
        if class_name.startswith("module_"):
            return None

        concrete_fields = concrete_named_tuple_fields(func_obj)
        func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
        init_type_hints = getattr(func_obj, "_pysymex_init_type_hints", None)
        if func_code is None and isinstance(func_obj, type):
            init_func = getattr(func_obj, "__init__", None)
            if init_func and hasattr(init_func, "__code__"):
                func_code = init_func.__code__

        if func_code is None:
            modeled_code = getattr(func_obj, "_modeled_object", None)
            if isinstance(modeled_code, types.CodeType):
                func_code = modeled_code

        modeled_cls = None
        if isinstance(func_obj, SymbolicValue):
            modeled_cls = modeled_class_from_value(func_obj)
        if concrete_fields is not None:
            modeled_cls = class_registry.register_class(SymbolicClass(class_name))
            configure_concrete_named_tuple_class(modeled_cls, concrete_fields)
        elif modeled_cls is None and isinstance(func_obj, type):
            modeled_cls = modeled_class_from_python_type(func_obj)
            if func_code is not None and class_registry.get_by_code_object(func_code) is None:
                class_registry.register_code_object(func_code, modeled_cls)
        elif modeled_cls is None and func_code is not None:
            modeled_cls = class_registry.get_by_code_object(func_code)
            if modeled_cls is None:
                modeled_cls = class_registry.register_class(SymbolicClass(class_name))
                class_registry.register_code_object(func_code, modeled_cls)
                register_class_body_methods(
                    modeled_cls, func_obj if isinstance(func_obj, type) else func_code
                )
                _apply_init_type_hints(modeled_cls, init_type_hints)
                if not modeled_cls.init_params and getattr(func_code, "co_name", "") != class_name:
                    params = extract_init_params(func_code)
                    if params:
                        modeled_cls.set_init_params(params)
                        _apply_init_type_hints(modeled_cls, init_type_hints)
        else:
            modeled_cls = class_registry.get_class(class_name)

        if modeled_cls is None:
            return None
        _apply_init_type_hints(modeled_cls, init_type_hints)
        if modeled_cls.is_abstract:
            return OpcodeResult.error(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {modeled_cls.abstract_instantiation_message()}",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )
            )
        named_tuple_error = named_tuple_call_error(modeled_cls, class_name, args, kwargs)
        if named_tuple_error is not None:
            return OpcodeResult.error(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {named_tuple_error}",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )
            )
        enum_result = try_literal_enum_constructor(
            instr, state, ctx, modeled_cls, class_registry, class_name, args, kwargs
        )
        if enum_result is not None:
            return enum_result

        if not bypass_metaclass:
            metaclass_result = _dispatch_custom_metaclass_call(
                instr,
                state,
                ctx,
                func_obj,
                args,
                kwargs,
                modeled_cls,
            )
            if metaclass_result is not None:
                return metaclass_result

        new_method = modeled_cls.lookup_method("__new__")
        if new_method is not None:
            retained_constructor_call = cast(
                "StackValue",
                (cast("StackValue", func_obj), tuple(args), dict(kwargs)),
            )
            new_result = perform_interprocedural_call_impl(
                state,
                ctx,
                new_method,
                [cast("StackValue", func_obj), *args],
                kwargs,
                protocol_method="__new__",
                protocol_retained_operand=retained_constructor_call,
            )
            if new_result is not None:
                return new_result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_CONSTRUCTION_PROTOCOL],
                fallback_events=[
                    unsupported_construction_event(
                        state=state,
                        reason=CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON,
                    )
                ],
                terminal=True,
            )

        kwargs_obj = cast("dict[str, object]", dict(kwargs))
        instance = class_registry.instantiate(modeled_cls, tuple(args), kwargs_obj, state.pc)

        result_val = modeled_instance_value(class_name, instance, state.pc)

        # Handle complex __init__ by performing an inter-procedural call.
        init_method = modeled_cls.lookup_method("__init__")
        init_callable = _modeled_method_callable(init_method)
        can_summarize_init = not (
            init_callable is not None
            and has_enabled_runtime_contract_obligations(
                init_callable,
                getattr(ctx, "config", None),
            )
        )
        if can_summarize_init and apply_straight_line_init_assignments(
            modeled_cls, instance, args, kwargs
        ):
            state = state.push(result_val)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        if init_method is not None:
            res = perform_interprocedural_call_impl(
                state,
                ctx,
                init_method,
                [result_val] + args,
                kwargs,
                is_init=True,
                init_instance=result_val,
            )
            if res:
                return res

        state = state.push(result_val)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    except (ImportError, AttributeError, TypeError, KeyError, z3.Z3Exception):
        return None
