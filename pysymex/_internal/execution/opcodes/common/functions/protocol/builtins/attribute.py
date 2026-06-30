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

"""Protocol-aware ``getattr``, ``setattr``, and ``delattr`` builtin dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.functions.protocol.builtins.object_getattribute import (
    dispatch_object_getattribute_builtin,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def route_attribute_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Route attribute-oriented builtins through modeled attribute protocols."""
    mutation_result = _dispatch_attribute_mutation_builtin(
        state,
        func_obj,
        model_name,
        args,
        kwargs,
        ctx,
    )
    if mutation_result is not None:
        return mutation_result
    object_getattribute_result = dispatch_object_getattribute_builtin(
        state,
        model_name,
        args,
        kwargs,
        ctx,
    )
    if object_getattribute_result is not None:
        return object_getattribute_result
    return _dispatch_missing_attribute_builtin(state, func_obj, model_name, args, kwargs, ctx)


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
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        set_declared_descriptor,
    )
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.mutation import (
        route_modeled_attribute_mutation,
    )
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.properties import (
        dispatch_modeled_property_mutation,
    )

    if len(args) == 3 and (model_name == "setattr" or func_obj is setattr):
        attr_name = SymbolicString.concrete_literal(args[1])
        if isinstance(args[0], SymbolicObject) and attr_name is not None:
            return _symbolic_object_setattr_result(state, args[0], attr_name, args[2])
        if isinstance(args[0], SymbolicValue):
            protocol_result = route_modeled_attribute_mutation(
                state,
                ctx,
                args[0],
                "__setattr__",
                [args[1], args[2]],
                protocol_method="__builtin_setattr__",
            )
            if protocol_result is not None:
                return protocol_result
            if attr_name is not None:
                descriptor_result = dispatch_modeled_property_mutation(
                    state,
                    ctx,
                    args[0],
                    attr_name,
                    "__descriptor_set__",
                    [args[2]],
                    protocol_method="__builtin_descriptor_set__",
                )
                if descriptor_result is not None:
                    return descriptor_result
                descriptor_result = set_declared_descriptor(
                    state,
                    ctx,
                    args[0],
                    attr_name,
                    "__set__",
                    [args[2]],
                    protocol_method="__builtin_descriptor_set__",
                )
                if descriptor_result is not None:
                    return descriptor_result
                from pysymex._internal.execution.opcodes.common.functions.attribute.store import (
                    set_modeled_class_attribute,
                )

                if set_modeled_class_attribute(args[0], attr_name, args[2]):
                    return _completed_setattr_result(state, args[0], attr_name)
    if len(args) == 2 and (model_name == "delattr" or func_obj is delattr):
        if isinstance(args[0], SymbolicValue):
            protocol_result = route_modeled_attribute_mutation(
                state,
                ctx,
                args[0],
                "__delattr__",
                [args[1]],
                protocol_method="__builtin_delattr__",
            )
            if protocol_result is not None:
                return protocol_result
            attr_name = SymbolicString.concrete_literal(args[1])
            if attr_name is not None:
                descriptor_result = dispatch_modeled_property_mutation(
                    state,
                    ctx,
                    args[0],
                    attr_name,
                    "__descriptor_delete__",
                    [],
                    protocol_method="__builtin_descriptor_delete__",
                )
                if descriptor_result is not None:
                    return descriptor_result
                return set_declared_descriptor(
                    state,
                    ctx,
                    args[0],
                    attr_name,
                    "__delete__",
                    [],
                    protocol_method="__builtin_descriptor_delete__",
                )
    return None


def _completed_setattr_result(
    state: VMState,
    receiver: object,
    attr_name: str,
) -> OpcodeResult:
    """Return the shared successful ``setattr`` builtin result."""
    from pysymex._internal.core.effects.events import WriteEvent, WriteKind
    from pysymex._internal.core.effects.locations import attribute_write_location
    from pysymex._internal.core.types.base import SymbolicNoneType

    location = attribute_write_location(state, receiver, attr_name)
    state = state.record_write_event(
        WriteEvent(
            WriteKind.ATTRIBUTE,
            location.name,
            state.pc,
            location.precise,
            "builtins.setattr",
        ),
    )
    state = state.push(SymbolicNoneType("none"))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _symbolic_object_setattr_result(
    state: VMState,
    receiver: object,
    attr_name: str,
    value: StackValue,
) -> OpcodeResult:
    """Apply ordinary ``setattr`` storage to a heap-backed symbolic object."""
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.execution.calls.object.maps import (
        is_object_map,
        map_set,
        map_to_stack_dict,
    )

    if isinstance(receiver, SymbolicObject) and receiver.address != -1:
        obj_state = state.load_heap(receiver.address)
        if obj_state is None:
            state = state.store_heap(receiver.address, {attr_name: value})
        elif is_object_map(obj_state):
            map_set(obj_state, attr_name, value)
            state = state.store_heap(receiver.address, map_to_stack_dict(obj_state))

    return _completed_setattr_result(state, receiver, attr_name)


def _getattr_protocol_method(
    *,
    has_default: bool,
    has_getattr_fallbacks: bool,
    descriptor: bool,
) -> str:
    """Return the retained protocol name for modeled getattr/descriptor dispatch."""
    prefix = "__descriptor_get" if descriptor else "__getattribute"
    if has_default and has_getattr_fallbacks:
        return f"{prefix}_getattr_default__"
    if has_getattr_fallbacks:
        return f"{prefix}_getattr__"
    if has_default:
        return f"{prefix}_default__"
    return f"{prefix}__"


def _getattr_or_property_builtin(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    default_value: StackValue | None,
    getattr_fallbacks: tuple[ProtocolCallCandidate, ...],
) -> OpcodeResult | None:
    """Dispatch modeled ``__getattribute__`` or property getter for builtin getattr."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.methods import (
        dispatch_modeled_getattribute,
    )
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.properties import (
        dispatch_modeled_property_getter,
    )
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    has_default = default_value is not None
    has_getattr = bool(getattr_fallbacks)
    if lookup_modeled_method(receiver, "__getattribute__") is not None:
        return dispatch_modeled_getattribute(
            state,
            ctx,
            receiver,
            attr_name,
            protocol_method=_getattr_protocol_method(
                has_default=has_default,
                has_getattr_fallbacks=has_getattr,
                descriptor=False,
            ),
            protocol_retained_operand=default_value,
            protocol_fallbacks=getattr_fallbacks,
        )

    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if not (isinstance(properties, dict) and attr_name in properties):
        return None
    return dispatch_modeled_property_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=_getattr_protocol_method(
            has_default=has_default,
            has_getattr_fallbacks=has_getattr,
            descriptor=True,
        ),
        protocol_retained_operand=default_value,
        protocol_fallbacks=getattr_fallbacks,
    )


def _getattr_data_descriptor_getters(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    default_value: StackValue | None,
    getattr_fallbacks: tuple[ProtocolCallCandidate, ...],
) -> OpcodeResult | None:
    """Dispatch class and data descriptor getters for builtin getattr."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_class_descriptor,
        get_declared_data_descriptor,
    )

    has_default = default_value is not None
    descriptor_method = _getattr_protocol_method(
        has_default=has_default,
        has_getattr_fallbacks=bool(getattr_fallbacks),
        descriptor=True,
    )
    for dispatcher in (
        get_declared_class_descriptor,
        get_declared_data_descriptor,
    ):
        descriptor_result = dispatcher(
            state,
            ctx,
            receiver,
            attr_name,
            protocol_method=descriptor_method,
            protocol_retained_operand=default_value,
            protocol_fallbacks=getattr_fallbacks,
        )
        if descriptor_result is not None:
            return descriptor_result
    return None


def _getattr_non_data_descriptor_getter(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    default_value: StackValue | None,
    getattr_fallbacks: tuple[ProtocolCallCandidate, ...],
) -> OpcodeResult | None:
    """Dispatch non-data descriptor getters for builtin getattr."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_non_data_descriptor,
    )

    has_default = default_value is not None
    descriptor_method = _getattr_protocol_method(
        has_default=has_default,
        has_getattr_fallbacks=bool(getattr_fallbacks),
        descriptor=True,
    )
    descriptor_result = get_declared_non_data_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_method,
        protocol_retained_operand=default_value,
        protocol_fallbacks=getattr_fallbacks,
    )
    if descriptor_result is not None:
        return descriptor_result
    return None


def _modeled_object_attribute_found(receiver: SymbolicValue, attr_name: str) -> bool:
    """Return whether the modeled object already has the requested attribute."""
    modeled_object = getattr(receiver, "_modeled_object", None)
    get_attribute = getattr(modeled_object, "get_attribute", None)
    if not callable(get_attribute):
        return False
    typed_get_attribute = cast(
        "Callable[[str, object | None], tuple[object, bool]]",
        get_attribute,
    )
    _value, found = typed_get_attribute(attr_name, receiver)
    return found


def _dispatch_missing_getattr_fallback(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    default_value: StackValue | None,
    has_getattr: bool,
) -> OpcodeResult | None:
    """Dispatch ``__getattr__`` fallback or builtin default return behavior."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.methods import (
        route_modeled_missing_attribute,
    )

    if default_value is not None:
        if has_getattr:
            return route_modeled_missing_attribute(
                state,
                ctx,
                receiver,
                attr_name,
                protocol_method="__getattr_default__",
                protocol_retained_operand=default_value,
            )
        return None
    return route_modeled_missing_attribute(state, ctx, receiver, attr_name)


def _dispatch_missing_attribute_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Route ``getattr`` through modeled descriptor and missing-attribute chains."""
    if len(args) not in {2, 3} or kwargs or ctx is None:
        return None
    if model_name != "getattr" and func_obj is not getattr:
        return None

    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.methods import (
        modeled_getattr_fallbacks,
    )

    receiver = args[0]
    attr_name = SymbolicString.concrete_literal(args[1])
    if not isinstance(receiver, SymbolicValue) or attr_name is None:
        return None

    default_value = args[2] if len(args) == 3 else None
    getattr_fallbacks = modeled_getattr_fallbacks(receiver, attr_name)
    direct_result = _getattr_or_property_builtin(
        state,
        ctx,
        receiver,
        attr_name,
        default_value,
        getattr_fallbacks,
    )
    if direct_result is not None:
        return direct_result

    data_descriptor_result = _getattr_data_descriptor_getters(
        state,
        ctx,
        receiver,
        attr_name,
        default_value,
        getattr_fallbacks,
    )
    if data_descriptor_result is not None:
        return data_descriptor_result

    if not _modeled_object_attribute_found(receiver, attr_name):
        non_data_descriptor_result = _getattr_non_data_descriptor_getter(
            state,
            ctx,
            receiver,
            attr_name,
            default_value,
            getattr_fallbacks,
        )
        if non_data_descriptor_result is not None:
            return non_data_descriptor_result

    return _dispatch_missing_getattr_fallback(
        state,
        ctx,
        receiver,
        attr_name,
        default_value,
        bool(getattr_fallbacks),
    )
