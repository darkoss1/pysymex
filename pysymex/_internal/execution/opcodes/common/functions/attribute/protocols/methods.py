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

"""Opcode-side dispatch for dynamic attribute read hooks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.functions.attribute.fallbacks import (
    unsupported_attribute_protocol,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.constants import (
    attribute_load_retained_operand,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.properties import (
    dispatch_modeled_property_getter,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def modeled_getattr_fallbacks(
    receiver: SymbolicValue,
    attr_name: str,
) -> tuple[ProtocolCallCandidate, ...]:
    """Return the retained ``__getattr__`` fallback for AttributeError lookup failures."""
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    if lookup_modeled_method(receiver, "__getattr__") is None:
        return ()
    return (ProtocolCallCandidate(receiver, "__getattr__", attr_name),)


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
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(receiver, "__getattribute__")
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
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
    return unsupported_attribute_protocol(
        state,
        reason=f"modeled __getattribute__ for {attr_name!r} could not be entered",
    )


def dispatch_modeled_attribute_read(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    push_null: bool = False,
) -> OpcodeResult | None:
    """Run always-on access hooks before modeled descriptors."""
    getattr_fallbacks = modeled_getattr_fallbacks(receiver, attr_name)
    retained_operand = attribute_load_retained_operand(push_null)
    getattribute_result = dispatch_modeled_getattribute(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method="__getattribute_getattr__" if getattr_fallbacks else "__getattribute__",
        protocol_retained_operand=retained_operand,
        protocol_fallbacks=getattr_fallbacks,
    )
    if getattribute_result is not None:
        return getattribute_result
    descriptor_protocol = (
        "__descriptor_get_getattr__" if getattr_fallbacks else "__descriptor_get__"
    )
    property_result = dispatch_modeled_property_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_protocol,
        protocol_retained_operand=retained_operand,
        protocol_fallbacks=getattr_fallbacks,
    )
    if property_result is not None:
        return property_result
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_data_descriptor,
    )

    return get_declared_data_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=descriptor_protocol,
        protocol_retained_operand=retained_operand,
        protocol_fallbacks=getattr_fallbacks,
    )


def dispatch_modeled_descriptor_fallback(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    push_null: bool = False,
) -> OpcodeResult | None:
    """Execute a non-data declared descriptor after instance lookup misses."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_non_data_descriptor,
    )

    getattr_fallbacks = modeled_getattr_fallbacks(receiver, attr_name)
    return get_declared_non_data_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method="__descriptor_get_getattr__" if getattr_fallbacks else "__descriptor_get__",
        protocol_retained_operand=attribute_load_retained_operand(push_null),
        protocol_fallbacks=getattr_fallbacks,
    )


def route_modeled_missing_attribute(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    protocol_method: str = "__getattr__",
    protocol_retained_operand: StackValue | None = None,
    push_null: bool = False,
) -> OpcodeResult | None:
    """Execute ``__getattr__`` after ordinary modeled lookup fails."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(receiver, "__getattr__")
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [attr_name],
        {},
        protocol_method=protocol_method,
        protocol_retained_operand=(
            protocol_retained_operand
            if protocol_retained_operand is not None
            else attribute_load_retained_operand(push_null)
        ),
    )
    if result is not None:
        return result
    return unsupported_attribute_protocol(
        state,
        reason=f"modeled __getattr__ for {attr_name!r} could not be entered",
    )
