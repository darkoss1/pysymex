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

"""Model direct ``object.__setattr__`` and ``object.__delattr__`` calls."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import attribute_write_location
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.helpers import concrete_string
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.attribute.protocols import (
    dispatch_modeled_property_mutation,
)
from pysymex.execution.opcodes.common.functions.classes import (
    copy_symbolic_value_with_modeled_object,
    replace_identity_references,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


def try_object_attribute_descriptor_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply direct object attribute descriptors when the call shape is definite."""
    if kwargs:
        return None
    if func_obj is object.__setattr__:
        return _object_setattr_result(instr, state, ctx, args)
    if func_obj is object.__delattr__:
        return _object_delattr_result(instr, state, ctx, args)
    return None


def _object_setattr_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    args: list[StackValue],
) -> OpcodeResult | None:
    if len(args) != 3:
        return None
    receiver, raw_attr_name, value = args
    attr_name = concrete_string(raw_attr_name)
    if attr_name is None:
        return None
    if isinstance(receiver, SymbolicValue):
        descriptor_result = dispatch_modeled_property_mutation(
            state,
            ctx,
            receiver,
            attr_name,
            "__descriptor_set__",
            [value],
        )
        if descriptor_result is not None:
            return descriptor_result
        cloned_receiver = copy_symbolic_value_with_modeled_object(receiver)
        if cloned_receiver is None:
            return None
        modeled_object = getattr(cloned_receiver, "_modeled_object", None)
        set_attribute = getattr(modeled_object, "set_attribute", None)
        if not callable(set_attribute) or not set_attribute(attr_name, value):
            return None
        replace_identity_references(state, receiver, cloned_receiver)
        return _attribute_mutation_result(instr, state, receiver, attr_name)
    try:
        object.__setattr__(receiver, attr_name, value)
    except (AttributeError, TypeError):
        return None
    return _attribute_mutation_result(instr, state, receiver, attr_name)


def _object_delattr_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    args: list[StackValue],
) -> OpcodeResult | None:
    if len(args) != 2:
        return None
    receiver, raw_attr_name = args
    attr_name = concrete_string(raw_attr_name)
    if attr_name is None:
        return None
    if isinstance(receiver, SymbolicValue):
        descriptor_result = dispatch_modeled_property_mutation(
            state,
            ctx,
            receiver,
            attr_name,
            "__descriptor_delete__",
            [],
        )
        if descriptor_result is not None:
            return descriptor_result
        cloned_receiver = copy_symbolic_value_with_modeled_object(receiver)
        if cloned_receiver is None:
            return None
        modeled_object = getattr(cloned_receiver, "_modeled_object", None)
        delete_attribute = getattr(modeled_object, "delete_attribute", None)
        if not callable(delete_attribute) or not delete_attribute(attr_name):
            return None
        replace_identity_references(state, receiver, cloned_receiver)
        return _attribute_mutation_result(instr, state, receiver, attr_name)
    try:
        object.__delattr__(receiver, attr_name)
    except (AttributeError, TypeError):
        return None
    return _attribute_mutation_result(instr, state, receiver, attr_name)


def _attribute_mutation_result(
    instr: dis.Instruction,
    state: VMState,
    receiver: object,
    attr_name: str,
) -> OpcodeResult:
    location = attribute_write_location(state, receiver, attr_name)
    state = state.record_write_event(
        WriteEvent(WriteKind.ATTRIBUTE, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.push(SymbolicNone("none"))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


__all__ = ["try_object_attribute_descriptor_call"]
