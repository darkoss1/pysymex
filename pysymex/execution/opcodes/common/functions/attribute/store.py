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

"""Implement ``STORE_ATTR`` / ``DELETE_ATTR`` for symbolic and modeled instances.

Writes declared descriptors, modeled slots, and concrete dict-backed attributes; routes
unsupported targets through explicit degradation tags rather than silent success.

Limitations:
    Does not model every CPython descriptor side effect (e.g. some data descriptors on types).
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import attribute_write_location
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.opcodes.common.functions.classes import (
    copy_symbolic_value_with_modeled_object,
    modeled_class_from_value,
    replace_identity_references,
)
from pysymex.execution.calls.helpers import (
    is_object_map,
    map_set,
    map_to_stack_dict,
)
from pysymex.execution.calls.model_dispatch import (
    path_is_sat,
    require_stack_depth,
    validate_concrete_attribute_access,
)
from pysymex.execution.opcodes.common.functions.attribute.protocols import (
    dispatch_modeled_attribute_mutation,
    dispatch_modeled_property_mutation,
)
from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
    dispatch_declared_descriptor_mutation,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object, updating heap memory."""

    require_stack_depth(state, instr, 2, "STORE_ATTR value and object")
    obj = state.pop()
    value = state.pop()
    attr_name = str(instr.argval)
    location = attribute_write_location(state, obj, attr_name)

    if isinstance(obj, SymbolicNone) or _is_definite_symbolic_none(obj, state):
        return _attribute_error_result(
            instr,
            state,
            ctx,
            f"'NoneType' object has no attribute '{attr_name}' "
            "and no __dict__ for setting new attributes",
        )

    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.load_heap(obj.address)
            if obj_state is None:
                state = state.store_heap(obj.address, {attr_name: value})
            elif is_object_map(obj_state):
                map_set(obj_state, attr_name, value)
                state = state.store_heap(obj.address, map_to_stack_dict(obj_state))
    elif isinstance(obj, SymbolicValue):
        protocol_result = dispatch_modeled_attribute_mutation(
            state, ctx, obj, "__setattr__", [attr_name, value]
        )
        if protocol_result is not None:
            return protocol_result
        descriptor_result = dispatch_modeled_property_mutation(
            state, ctx, obj, attr_name, "__descriptor_set__", [value]
        )
        if descriptor_result is not None:
            return descriptor_result
        descriptor_result = dispatch_declared_descriptor_mutation(
            state, ctx, obj, attr_name, "__set__", [value]
        )
        if descriptor_result is not None:
            return descriptor_result
        if _set_modeled_class_attribute(obj, attr_name, value):
            pass
        else:
            cloned_obj = copy_symbolic_value_with_modeled_object(obj)
            if cloned_obj is not None:
                modeled_object = getattr(cloned_obj, "_modeled_object", None)
                set_attribute = getattr(modeled_object, "set_attribute", None)
                if callable(set_attribute):
                    if not set_attribute(attr_name, value):
                        cls = getattr(modeled_object, "cls", None)
                        cls_name = getattr(cls, "name", type(obj).__name__)
                        if bool(getattr(cls, "dataclass_frozen", False)):
                            return _attribute_error_result(
                                instr, state, ctx, f"cannot assign to field '{attr_name}'"
                            )
                        return _attribute_error_result(
                            instr,
                            state,
                            ctx,
                            f"property '{attr_name}' of '{cls_name}' object has no setter",
                        )
                    replace_identity_references(state, obj, cloned_obj)
    else:
        validate_concrete_attribute_access(attr_name)
        try:
            setattr(obj, attr_name, value)
        except AttributeError as exc:
            return _attribute_exception_result(instr, state, ctx, IssueKind.ATTRIBUTE_ERROR, exc)
        except TypeError as exc:
            return _attribute_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except Exception as exc:
            return _attribute_exception_result(
                instr, state, ctx, IssueKind.UNHANDLED_EXCEPTION, exc
            )
    state = state.record_write_event(
        WriteEvent(WriteKind.ATTRIBUTE, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete attribute from object."""
    require_stack_depth(state, instr, 1, "DELETE_ATTR object")
    obj = state.pop()
    attr_name = str(instr.argval)
    location = attribute_write_location(state, obj, attr_name)

    if isinstance(obj, SymbolicNone) or _is_definite_symbolic_none(obj, state):
        return _attribute_error_result(
            instr,
            state,
            ctx,
            f"'NoneType' object has no attribute '{attr_name}' "
            "and no __dict__ for setting new attributes",
        )

    if isinstance(obj, SymbolicObject) and obj.address != -1:
        obj_state = state.load_heap(obj.address)
        if isinstance(obj_state, dict) and attr_name in obj_state:
            updated = dict(cast("dict[str, StackValue]", obj_state))
            del updated[attr_name]
            state = state.store_heap(obj.address, updated)
    elif isinstance(obj, SymbolicValue):
        protocol_result = dispatch_modeled_attribute_mutation(
            state, ctx, obj, "__delattr__", [attr_name]
        )
        if protocol_result is not None:
            return protocol_result
        descriptor_result = dispatch_modeled_property_mutation(
            state, ctx, obj, attr_name, "__descriptor_delete__", []
        )
        if descriptor_result is not None:
            return descriptor_result
        descriptor_result = dispatch_declared_descriptor_mutation(
            state, ctx, obj, attr_name, "__delete__", []
        )
        if descriptor_result is not None:
            return descriptor_result
        cloned_obj = copy_symbolic_value_with_modeled_object(obj)
        if cloned_obj is not None:
            modeled_object = getattr(cloned_obj, "_modeled_object", None)
            delete_attribute = getattr(modeled_object, "delete_attribute", None)
            if callable(delete_attribute):
                if not delete_attribute(attr_name):
                    cls = getattr(modeled_object, "cls", None)
                    cls_name = getattr(cls, "name", type(obj).__name__)
                    if bool(getattr(cls, "dataclass_frozen", False)):
                        return _attribute_error_result(
                            instr, state, ctx, f"cannot delete field '{attr_name}'"
                        )
                    return _attribute_error_result(
                        instr,
                        state,
                        ctx,
                        f"'{cls_name}' object has no attribute '{attr_name}'",
                    )
                replace_identity_references(state, obj, cloned_obj)
    else:
        validate_concrete_attribute_access(attr_name)
        try:
            delattr(obj, attr_name)
        except AttributeError as exc:
            return _attribute_exception_result(instr, state, ctx, IssueKind.ATTRIBUTE_ERROR, exc)
        except TypeError as exc:
            return _attribute_exception_result(instr, state, ctx, IssueKind.TYPE_ERROR, exc)
        except Exception as exc:
            return _attribute_exception_result(
                instr, state, ctx, IssueKind.UNHANDLED_EXCEPTION, exc
            )
    state = state.record_write_event(
        WriteEvent(WriteKind.ATTRIBUTE, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _is_definite_symbolic_none(obj: object, state: VMState) -> bool:
    """Return whether path constraints prove *obj* is definitely ``None``."""
    return isinstance(obj, SymbolicValue) and not path_is_sat(
        [*state.path_constraints, z3.Not(obj.is_none)]
    )


def _set_modeled_class_attribute(
    obj: SymbolicValue,
    attr_name: str,
    value: StackValue,
) -> bool:
    """Store a runtime class-object attribute in the modeled class registry."""
    modeled_cls = modeled_class_from_value(obj)
    if modeled_cls is None:
        return False
    modeled_cls.add_class_attr(attr_name, value)
    return True


def _attribute_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str,
) -> OpcodeResult:
    """Route an ``AttributeError`` through the shared attribute-exception result path."""
    return _attribute_exception_result(
        instr,
        state,
        ctx,
        IssueKind.ATTRIBUTE_ERROR,
        AttributeError(message),
    )


def _attribute_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    kind: IssueKind,
    exc: Exception,
) -> OpcodeResult:
    """Jump to a handler for *exc* or report it as a feasible detector issue."""
    modeled_exc = SymbolicException.concrete(type(exc), str(exc), raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=kind,
        message=f"Possible {type(exc).__name__}: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
