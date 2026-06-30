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

"""Protocol-aware model for exact ``object.__getattribute__`` calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import attribute_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_object_getattribute_builtin(
    state: VMState,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Execute base-object lookup for exact ``object.__getattribute__`` calls."""
    if model_name != "object.__getattribute__" or kwargs or len(args) != 2 or ctx is None:
        return None

    receiver = args[0]
    attr_name = SymbolicString.concrete_literal(args[1])
    if not isinstance(receiver, SymbolicValue) or attr_name is None:
        return None
    return _dispatch_base_object_getattribute(state, ctx, receiver, attr_name)


def _dispatch_base_object_getattribute(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
) -> OpcodeResult:
    """Run CPython base-object lookup without invoking custom ``__getattribute__``."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_class_descriptor,
        get_declared_data_descriptor,
        get_declared_non_data_descriptor,
    )
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.properties import (
        dispatch_modeled_property_getter,
    )

    property_result = dispatch_modeled_property_getter(state, ctx, receiver, attr_name)
    if property_result is not None:
        return property_result
    descriptor_result = get_declared_class_descriptor(state, ctx, receiver, attr_name)
    if descriptor_result is not None:
        return descriptor_result
    descriptor_result = get_declared_data_descriptor(state, ctx, receiver, attr_name)
    if descriptor_result is not None:
        return descriptor_result

    modeled_object = getattr(receiver, "_modeled_object", None)
    get_attribute = getattr(modeled_object, "get_attribute", None)
    if callable(get_attribute):
        typed_get_attribute = cast(
            "Callable[[str, object | None], tuple[object, bool]]",
            get_attribute,
        )
        attr_value, found = typed_get_attribute(attr_name, receiver)
        if found:
            state = state.push(coerce_call_stack_value(attr_value))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    descriptor_result = get_declared_non_data_descriptor(state, ctx, receiver, attr_name)
    if descriptor_result is not None:
        return descriptor_result
    return _attribute_error_result(state, ctx, receiver, attr_name)


def _attribute_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
) -> OpcodeResult:
    """Propagate a base-object ``AttributeError`` through handlers and protocol frames."""
    instr = ctx.get_instruction(state.pc)
    message = f"{receiver.name!r} object has no attribute {attr_name!r}"
    if instr is not None:
        handler_state = ExceptionFlow.jump_to_handler(
            state,
            ctx,
            instr.offset,
            attribute_error(message, state=state, instr=instr),
        )
        if handler_state is not None:
            return OpcodeResult.continue_with(handler_state)
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.ATTRIBUTE_ERROR,
            message=f"Possible AttributeError: {message}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
    )
