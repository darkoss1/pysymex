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

"""Model ``hasattr`` on instances with declared data/non-data descriptors.

Probes getter dispatch without executing arbitrary Python; returns a definite boolean only
when descriptor presence is known from static class metadata.

Limitations:
    Symbolic attribute names and unknown descriptor sets return ``None`` for generic handling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
    get_declared_class_descriptor,
    get_declared_data_descriptor,
    get_declared_non_data_descriptor,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def dispatch_declared_descriptor_hasattr(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Execute retained descriptor lookup for ``hasattr()`` when required."""
    if len(args) != 2 or kwargs or ctx is None:
        return None
    if model_name != "hasattr" and func_obj is not hasattr:
        return None

    receiver = args[0]
    attr_name = SymbolicString.concrete_literal(args[1])
    if not isinstance(receiver, SymbolicValue) or attr_name is None:
        return None
    false_value = SymbolicValue.from_const(False)
    descriptor_result = get_declared_class_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method="__descriptor_hasattr__",
        protocol_retained_operand=false_value,
    )
    if descriptor_result is not None:
        return descriptor_result
    descriptor_result = get_declared_data_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method="__descriptor_hasattr__",
        protocol_retained_operand=false_value,
    )
    if descriptor_result is not None:
        return descriptor_result
    modeled_object = getattr(receiver, "_modeled_object", None)
    get_attribute = getattr(modeled_object, "get_attribute", None)
    if callable(get_attribute):
        typed_get_attribute = cast(
            "Callable[[str, object | None], tuple[object, bool]]",
            get_attribute,
        )
        _value, found = typed_get_attribute(attr_name, receiver)
        if found:
            return None
    return get_declared_non_data_descriptor(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method="__descriptor_hasattr__",
        protocol_retained_operand=false_value,
    )
