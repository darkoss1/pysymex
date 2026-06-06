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

"""Suspend and resume dynamic attribute protocol chains (``getattr``, descriptors).

Schedules interprocedural calls for ``__getattribute__``, ``__getattr__``, and descriptor
``__get__`` when static resolution fails. Cooperates with
:mod:`pysymex.execution.opcodes.common.control.protocol.negotiation` for ``NotImplemented``
fallbacks.

Limitations:
    Chained-default protocol method names are a fixed allowlist; unknown chains degrade.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.attribute.fallbacks import (
    unsupported_attribute_protocol_result,
    unsupported_descriptor_protocol_result,
)
from pysymex.models.objects import MethodType, SymbolicMethod

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.types.scalars.values import SymbolicValue
    from pysymex.core.state.record import VMState
    from pysymex.core.state.types import ProtocolCallCandidate
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS = frozenset(
    {
        "__descriptor_get_getattr_default__",
        "__getattribute_getattr_default__",
    }
)
GETATTR_DEFAULT_PROTOCOL_METHODS = (
    frozenset(
        {
            "__descriptor_get_default__",
            "__getattr_default__",
            "__getattribute_default__",
            "__descriptor_hasattr__",
        }
    )
    | GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS
)


def dispatch_modeled_attribute_mutation(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    method_name: str,
    args: list[StackValue],
) -> OpcodeResult | None:
    """Execute a custom attribute mutation hook before ordinary storage."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(receiver, method_name)
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        args,
        {},
        protocol_method=method_name,
    )
    if result is not None:
        return result
    return unsupported_attribute_protocol_result(
        state,
        reason=f"modeled attribute mutation {method_name!r} could not be entered",
    )


def dispatch_modeled_property_getter(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    protocol_method: str = "__descriptor_get__",
    protocol_retained_operand: StackValue | None = None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = (),
) -> OpcodeResult | None:
    """Execute a retained property getter body when available."""
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if not isinstance(properties, dict) or attr_name not in properties:
        return None
    descriptor = cast("dict[str, object]", properties)[attr_name]
    getter_func = getattr(descriptor, "getter_func", None)
    getter_code = getattr(descriptor, "getter_code", None)
    from pysymex.execution.calls.payload import function_payload

    getter_payload = function_payload(getter_code)
    if not callable(getter_func) and getter_payload is None:
        return unsupported_descriptor_protocol_result(
            state,
            reason=f"property {attr_name!r} has no retained getter code",
        )
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        SymbolicMethod(
            attr_name,
            getter_func if callable(getter_func) else getter_payload,
            method_type=MethodType.INSTANCE,
        ).bind_to_instance(receiver),
        [],
        {},
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
    )
    if result is not None:
        return result
    return unsupported_descriptor_protocol_result(
        state,
        reason=f"property getter {attr_name!r} could not be entered",
    )


def dispatch_modeled_getattribute(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    protocol_method: str = "__getattribute__",
    protocol_retained_operand: StackValue | None = None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = (),
) -> OpcodeResult | None:
    """Execute an always-on custom ``__getattribute__`` hook."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(receiver, "__getattribute__")
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [attr_name],
        {},
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
    )
    if result is not None:
        return result
    return unsupported_attribute_protocol_result(
        state,
        reason=f"modeled __getattribute__ for {attr_name!r} could not be entered",
    )


def dispatch_modeled_attribute_read(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
) -> OpcodeResult | None:
    """Run always-on access hooks before modeled descriptors."""
    getattribute_result = dispatch_modeled_getattribute(state, ctx, receiver, attr_name)
    if getattribute_result is not None:
        return getattribute_result
    property_result = dispatch_modeled_property_getter(state, ctx, receiver, attr_name)
    if property_result is not None:
        return property_result
    from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
        dispatch_declared_data_descriptor_getter,
    )

    return dispatch_declared_data_descriptor_getter(state, ctx, receiver, attr_name)


def dispatch_modeled_property_mutation(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    method_name: str,
    args: list[StackValue],
) -> OpcodeResult | None:
    """Execute a retained property setter or deleter body."""
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if not isinstance(properties, dict) or attr_name not in properties:
        return None
    descriptor = cast("dict[str, object]", properties)[attr_name]
    code_name = "setter_code" if method_name == "__descriptor_set__" else "deleter_code"
    func_name = "setter_func" if method_name == "__descriptor_set__" else "deleter_func"
    method_func = getattr(descriptor, func_name, None)
    method_code = getattr(descriptor, code_name, None)
    from pysymex.execution.calls.payload import function_payload

    method_payload = function_payload(method_code)
    if not callable(method_func) and method_payload is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        SymbolicMethod(
            attr_name,
            method_func if callable(method_func) else method_payload,
            method_type=MethodType.INSTANCE,
        ).bind_to_instance(receiver),
        args,
        {},
        protocol_method=method_name,
    )
    if result is not None:
        return result
    return unsupported_descriptor_protocol_result(
        state,
        reason=f"property {method_name!r} for {attr_name!r} could not be entered",
    )


def dispatch_modeled_descriptor_fallback(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
) -> OpcodeResult | None:
    """Execute a non-data declared descriptor after instance lookup misses."""
    from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
        dispatch_declared_non_data_descriptor_getter,
    )

    return dispatch_declared_non_data_descriptor_getter(state, ctx, receiver, attr_name)


def dispatch_modeled_missing_attribute(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    protocol_method: str = "__getattr__",
    protocol_retained_operand: StackValue | None = None,
) -> OpcodeResult | None:
    """Execute ``__getattr__`` after ordinary modeled lookup fails."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(receiver, "__getattr__")
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [attr_name],
        {},
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
    )
    if result is not None:
        return result
    return unsupported_attribute_protocol_result(
        state,
        reason=f"modeled __getattr__ for {attr_name!r} could not be entered",
    )


__all__ = [
    "GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS",
    "GETATTR_DEFAULT_PROTOCOL_METHODS",
    "dispatch_modeled_attribute_read",
    "dispatch_modeled_attribute_mutation",
    "dispatch_modeled_descriptor_fallback",
    "dispatch_modeled_getattribute",
    "dispatch_modeled_missing_attribute",
    "dispatch_modeled_property_mutation",
    "dispatch_modeled_property_getter",
]
