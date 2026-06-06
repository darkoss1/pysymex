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

"""Intercept builtin calls that implement dunder protocols (``len``, ``iter``, conversions).

When bytecode calls a builtin wrapper around ``__len__``, ``__int__``, ``__iter__``, or
attribute mutation helpers, this module suspends into modeled user methods when the receiver
is a :class:`~pysymex.models.objects.SymbolicInstance`.

Limitations:
    Only registered protocol/builtin pairings are handled; unknown builtins defer to generic calls.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.protocol.fallbacks import (
    UNSUPPORTED_CONVERSION_PROTOCOL,
    UNSUPPORTED_ITERATION_PROTOCOL,
    UNSUPPORTED_LENGTH_PROTOCOL,
    protocol_builtin_fallback_events,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _dispatch_attribute_mutation_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Route ``setattr``/``delattr`` builtins to modeled attribute and descriptor mutation."""
    if kwargs or ctx is None:
        return None
    from pysymex.core.types.scalars.values import SymbolicValue
    from pysymex.models.builtins.extended.helpers import literal_string_value
    from pysymex.execution.opcodes.common.functions.attribute.protocols import (
        dispatch_modeled_attribute_mutation,
        dispatch_modeled_property_mutation,
    )
    from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
        dispatch_declared_descriptor_mutation,
    )

    if len(args) == 3 and (model_name == "setattr" or func_obj is setattr):
        if isinstance(args[0], SymbolicValue):
            protocol_result = dispatch_modeled_attribute_mutation(
                state, ctx, args[0], "__setattr__", [args[1], args[2]]
            )
            if protocol_result is not None:
                return protocol_result
            attr_name = literal_string_value(args[1])
            if attr_name is not None:
                descriptor_result = dispatch_modeled_property_mutation(
                    state, ctx, args[0], attr_name, "__descriptor_set__", [args[2]]
                )
                if descriptor_result is not None:
                    return descriptor_result
                return dispatch_declared_descriptor_mutation(
                    state, ctx, args[0], attr_name, "__set__", [args[2]]
                )
    if len(args) == 2 and (model_name == "delattr" or func_obj is delattr):
        if isinstance(args[0], SymbolicValue):
            protocol_result = dispatch_modeled_attribute_mutation(
                state, ctx, args[0], "__delattr__", [args[1]]
            )
            if protocol_result is not None:
                return protocol_result
            attr_name = literal_string_value(args[1])
            if attr_name is not None:
                descriptor_result = dispatch_modeled_property_mutation(
                    state, ctx, args[0], attr_name, "__descriptor_delete__", []
                )
                if descriptor_result is not None:
                    return descriptor_result
                return dispatch_declared_descriptor_mutation(
                    state, ctx, args[0], attr_name, "__delete__", []
                )
    return None


def _dispatch_missing_attribute_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Route ``getattr`` through modeled getattribute, descriptor, and missing-attribute chains."""
    if len(args) not in {2, 3} or kwargs or ctx is None:
        return None
    if model_name != "getattr" and func_obj is not getattr:
        return None
    from pysymex.core.types.scalars.values import SymbolicValue
    from pysymex.models.builtins.extended.helpers import literal_string_value

    receiver = args[0]
    attr_name = literal_string_value(args[1])
    if not isinstance(receiver, SymbolicValue) or attr_name is None:
        return None
    from pysymex.execution.opcodes.common.functions.attribute.protocols import (
        dispatch_modeled_getattribute,
        dispatch_modeled_missing_attribute,
        dispatch_modeled_property_getter,
    )
    from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
        dispatch_declared_class_descriptor_getter,
        dispatch_declared_data_descriptor_getter,
        dispatch_declared_non_data_descriptor_getter,
    )

    from pysymex.core.state.types import ProtocolCallCandidate
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    has_default = len(args) == 3
    default_value = args[2] if has_default else None
    has_getattr = lookup_modeled_method(receiver, "__getattr__") is not None
    chained_fallbacks = (
        (ProtocolCallCandidate(receiver, "__getattr__", attr_name),)
        if has_default and has_getattr
        else ()
    )
    if lookup_modeled_method(receiver, "__getattribute__") is not None:
        return dispatch_modeled_getattribute(
            state,
            ctx,
            receiver,
            attr_name,
            protocol_method=(
                "__getattribute_getattr_default__"
                if chained_fallbacks
                else "__getattribute_default__"
                if has_default
                else "__getattribute__"
            ),
            protocol_retained_operand=default_value,
            protocol_fallbacks=chained_fallbacks,
        )
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if isinstance(properties, dict) and attr_name in properties:
        property_result = dispatch_modeled_property_getter(
            state,
            ctx,
            receiver,
            attr_name,
            protocol_method=(
                "__descriptor_get_getattr_default__"
                if chained_fallbacks
                else "__descriptor_get_default__"
                if has_default
                else "__descriptor_get__"
            ),
            protocol_retained_operand=default_value,
            protocol_fallbacks=chained_fallbacks,
        )
        if property_result is not None:
            return property_result
    descriptor_method = (
        "__descriptor_get_getattr_default__"
        if chained_fallbacks
        else "__descriptor_get_default__"
        if has_default
        else "__descriptor_get__"
    )
    descriptor_result = dispatch_declared_class_descriptor_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_method,
        protocol_retained_operand=default_value,
        protocol_fallbacks=chained_fallbacks,
    )
    if descriptor_result is not None:
        return descriptor_result
    descriptor_result = dispatch_declared_data_descriptor_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_method,
        protocol_retained_operand=default_value,
        protocol_fallbacks=chained_fallbacks,
    )
    if descriptor_result is not None:
        return descriptor_result
    get_attribute = getattr(modeled_object, "get_attribute", None)
    if not callable(get_attribute):
        return None
    typed_get_attribute = cast(
        "Callable[[str, object | None], tuple[object, bool]]",
        get_attribute,
    )
    _value, found = typed_get_attribute(attr_name, receiver)
    if found:
        return None
    descriptor_result = dispatch_declared_non_data_descriptor_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_method,
        protocol_retained_operand=default_value,
        protocol_fallbacks=chained_fallbacks,
    )
    if descriptor_result is not None:
        return descriptor_result
    if has_default:
        if has_getattr:
            return dispatch_modeled_missing_attribute(
                state,
                ctx,
                receiver,
                attr_name,
                protocol_method="__getattr_default__",
                protocol_retained_operand=default_value,
            )
        return None
    return dispatch_modeled_missing_attribute(state, ctx, receiver, attr_name)


def _dispatch_unary_protocol_method(
    state: VMState,
    ctx: OpcodeDispatcher,
    value: StackValue,
    method_name: str,
    protocol_method: str,
    unsupported_marker: str,
) -> OpcodeResult | None:
    """Call a modeled unary dunder for protocol builtins such as ``len`` or ``iter``."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(value, method_name)
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [],
        {},
        protocol_method=protocol_method,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[unsupported_marker],
        fallback_events=protocol_builtin_fallback_events(
            state=state,
            degraded_pass=unsupported_marker,
        ),
        terminal=True,
    )


def dispatch_modeled_protocol_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Execute object protocol methods required by protocol-aware builtins."""
    from pysymex.execution.opcodes.common.functions.attribute.descriptor_hasattr import (
        dispatch_declared_descriptor_hasattr,
    )

    hasattr_result = dispatch_declared_descriptor_hasattr(
        state, func_obj, model_name, args, kwargs, ctx
    )
    if hasattr_result is not None:
        return hasattr_result
    mutation_result = _dispatch_attribute_mutation_builtin(
        state, func_obj, model_name, args, kwargs, ctx
    )
    if mutation_result is not None:
        return mutation_result
    missing_result = _dispatch_missing_attribute_builtin(
        state, func_obj, model_name, args, kwargs, ctx
    )
    if missing_result is not None:
        return missing_result
    if len(args) != 1 or kwargs or ctx is None:
        return None
    if model_name == "bool" or func_obj is bool:
        from pysymex.execution.opcodes.common.control.feasibility import (
            try_dispatch_modeled_truth_protocol,
        )

        return try_dispatch_modeled_truth_protocol(args[0], state, ctx)
    if model_name == "len" or func_obj is len:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__len__",
            "__len_value__",
            UNSUPPORTED_LENGTH_PROTOCOL,
        )
    if model_name == "int" or func_obj is int:
        result = _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__int__",
            "__int_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
        if result is not None:
            return result
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__index__",
            "__index_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
    if model_name == "float" or func_obj is float:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__float__",
            "__float_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
    if model_name == "iter" or func_obj is iter:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__iter__",
            "__iter__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    if model_name == "next" or func_obj is next:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__next__",
            "__next_value__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    if model_name == "reversed" or func_obj is reversed:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__reversed__",
            "__reversed__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    return None


__all__ = ["dispatch_modeled_protocol_builtin"]
