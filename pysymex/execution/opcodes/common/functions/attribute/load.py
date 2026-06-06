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

"""Implement ``LOAD_ATTR`` and related attribute reads for symbolic objects.

Resolves concrete attributes, modeled class fields, descriptor ``__get__``, and havoc loads
when precision is unknown. May suspend into interprocedural protocol calls for dynamic
``getattr`` / descriptor chains.

Side Effects:
    May fork paths, add constraints, or push call frames via protocol dispatch.
"""

from __future__ import annotations

import dis
import sys
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.memory.cow.collections import CowDict
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.opcodes.common.functions.attribute.declared_descriptors import (
    dispatch_declared_class_descriptor_getter,
)
from pysymex.execution.opcodes.common.functions.attribute.havoc import load_havoc_attribute
from pysymex.execution.opcodes.common.functions.attribute.protocols import (
    dispatch_modeled_attribute_read,
    dispatch_modeled_descriptor_fallback,
    dispatch_modeled_missing_attribute,
)
from pysymex.execution.opcodes.common.functions.classes import class_level_modeled_attribute
from pysymex.models.builtins.extended.namespace import ModeledSuperProxy
from pysymex.execution.calls.helpers import (
    as_stack_value,
    bind_heap_modeled_method,
    is_object_map,
    map_get,
    map_set,
    map_to_stack_dict,
)
from pysymex.execution.calls.model_dispatch import (
    can_constrain_receiver_non_none_without_solver,
    path_is_sat,
    resolve_model,
    validate_concrete_attribute_access,
)
from pysymex.models.stdlib.pathlib.core import (
    PATH_STRING_PREFIXES,
    PATH_STRING_STRING_PROPERTIES,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_load_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load an attribute or method, checking heap memory for attributes."""

    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()

    attr_name = str(instr.argval)
    push_null = False
    obj_state: StackValue | None = None
    if instr.opname == "LOAD_METHOD" and instr.arg is not None:
        push_null = True
    elif sys.version_info >= (3, 12) and hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True

    if isinstance(obj, SymbolicNone) or obj is None:
        if hasattr(None, attr_name):
            result_val = getattr(None, attr_name)
            if push_null:
                state = state.push(SymbolicNone())
            state = state.push(as_stack_value(result_val))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        return _none_attribute_error_result(instr, state, ctx, attr_name)

    if not isinstance(
        obj,
        (
            HavocValue,
            SymbolicObject,
            SymbolicBytes,
            SymbolicList,
            SymbolicDict,
            SymbolicString,
            SymbolicValue,
            SymbolicNone,
        ),
    ):
        if isinstance(obj, bytes):
            model_name = f"bytes.{attr_name}"
            if resolve_model(model_name):
                res_val = _modeled_attribute_carrier(f"{type(obj).__name__}_{attr_name}")
                res_val.model_name = model_name
                state = state.push(res_val)
                if push_null:
                    state = state.push(obj)
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)
        validate_concrete_attribute_access(attr_name)
        try:
            result_val = getattr(obj, attr_name)
        except AttributeError:
            result_val, type_constraint = SymbolicValue.symbolic(
                f"{type(obj).__name__}_{attr_name}"
            )
            state = state.add_constraint(type_constraint)
        if push_null:
            state = state.push(SymbolicNone())
        state = state.push(as_stack_value(result_val))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(obj, HavocValue):
        return load_havoc_attribute(state, obj, attr_name, push_null=push_null)

    result_val: object = None
    type_name = "unknown"
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.load_heap(obj.address)
            if isinstance(obj_state, SymbolicList):
                type_name = getattr(obj_state, "_type", None) or "list"
            elif isinstance(obj_state, SymbolicDict):
                type_name = "dict"
            elif obj_state is None:
                typed_obj_state: dict[str, StackValue] = {}
                obj_state = typed_obj_state
                state = state.store_heap(obj.address, obj_state)
            elif is_object_map(obj_state):
                _module_found, module_name_obj = map_get(obj_state, "__module_name__")
                if isinstance(module_name_obj, str) and module_name_obj:
                    type_name = module_name_obj
            if type_name != "unknown":
                model_name = f"{type_name}.{attr_name}"
                if resolve_model(model_name):
                    res_val = _modeled_attribute_carrier(
                        f"{getattr(obj, 'name', 'obj')}.{attr_name}"
                    )
                    res_val.model_name = model_name
                    state = state.push(res_val)
                    if push_null:
                        state = state.push(obj)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)

            if is_object_map(obj_state):
                found_attr, raw_attr_value = map_get(obj_state, attr_name)
            else:
                found_attr = False
                raw_attr_value = None
            if found_attr:
                result_val = as_stack_value(bind_heap_modeled_method(raw_attr_value, obj))
            else:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                if is_object_map(obj_state):
                    map_set(obj_state, attr_name, result_val)
                    state = state.store_heap(obj.address, map_to_stack_dict(obj_state))
                state = state.add_constraint(type_constraint)
        else:
            addresses = list(obj.potential_addresses)
            if not addresses:
                result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                state = state.add_constraint(type_constraint)
            else:
                values: list[tuple[object, object]] = []
                for addr in addresses:
                    mem_obj = state.load_heap(addr)
                    if is_object_map(mem_obj):
                        found_attr, raw_attr_value = map_get(mem_obj, attr_name)
                    else:
                        found_attr = False
                        raw_attr_value = None
                    if found_attr:
                        val = as_stack_value(bind_heap_modeled_method(raw_attr_value, obj))
                    else:
                        val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
                        if is_object_map(mem_obj):
                            map_set(mem_obj, attr_name, val)
                            state = state.store_heap(addr, map_to_stack_dict(mem_obj))
                        else:
                            state = state.store_heap(addr, {attr_name: val})
                    values.append((addr, val))
                if len(values) == 1:
                    result_val = values[0][1]
                else:
                    _base_addr, base_val = values[-1]
                    if not isinstance(base_val, SymbolicValue):
                        base_val = SymbolicValue.from_const(base_val)
                    merged_z3_int = base_val.z3_int
                    merged_z3_bool = base_val.z3_bool
                    merged_is_int = base_val.is_int
                    merged_is_bool = base_val.is_bool
                    for addr, val in reversed(values[:-1]):
                        if not isinstance(val, SymbolicValue):
                            val = SymbolicValue.from_const(val)
                        cond = obj.z3_addr == addr
                        merged_z3_int = z3.If(cond, val.z3_int, merged_z3_int)
                        merged_z3_bool = z3.If(cond, val.z3_bool, merged_z3_bool)
                        merged_is_int = z3.If(cond, val.is_int, merged_is_int)
                        merged_is_bool = z3.If(cond, val.is_bool, merged_is_bool)
                    result_val = SymbolicValue(
                        _name=f"{obj.name}.{attr_name}",
                        z3_int=merged_z3_int,
                        is_int=merged_is_int,
                        z3_bool=merged_z3_bool,
                        is_bool=merged_is_bool,
                    )
    elif isinstance(obj, SymbolicList):
        type_name = getattr(obj, "_type", None) or "list"
    elif isinstance(obj, SymbolicBytes):
        type_name = "bytes"
    elif isinstance(obj, SymbolicDict):
        type_name = "dict"
    elif isinstance(obj, SymbolicString):
        path_attribute = _load_path_string_attribute(obj, attr_name)
        if path_attribute is not None:
            result_value, constraint = path_attribute
            state = state.push(result_value)
            state = state.add_constraint(constraint)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        type_name = "str"
    elif isinstance(obj, SymbolicValue):
        modeled_object = getattr(obj, "_modeled_object", None)
        if isinstance(modeled_object, ModeledSuperProxy):
            from pysymex.execution.opcodes.common.functions.super import (
                handle_modeled_super_proxy_attr,
            )

            return handle_modeled_super_proxy_attr(
                instr,
                state,
                ctx,
                modeled_object,
                push_null=push_null,
            )
        descriptor_result = dispatch_modeled_attribute_read(state, ctx, obj, attr_name)
        if descriptor_result is not None:
            return descriptor_result
        descriptor_result = dispatch_declared_class_descriptor_getter(state, ctx, obj, attr_name)
        if descriptor_result is not None:
            return descriptor_result
        class_attr_value, class_attr_found = class_level_modeled_attribute(obj, attr_name)
        if class_attr_found:
            result_val = as_stack_value(class_attr_value)
        if (
            result_val is None
            and modeled_object is not None
            and hasattr(modeled_object, "get_attribute")
        ):
            get_attribute = getattr(modeled_object, "get_attribute")
            attr_value, found = get_attribute(attr_name, bound_instance=obj)
            if found:
                result_val = as_stack_value(attr_value)
            else:
                descriptor_result = dispatch_modeled_descriptor_fallback(state, ctx, obj, attr_name)
                if descriptor_result is not None:
                    return descriptor_result
                dynamic_result = dispatch_modeled_missing_attribute(state, ctx, obj, attr_name)
                if dynamic_result is not None:
                    return dynamic_result
                return _attribute_error_result(
                    instr,
                    state,
                    ctx,
                    f"'{obj.name}' object has no attribute '{attr_name}'",
                )
        object_type = obj.type_tag
        if object_type in {"int", "bool"} or z3.is_true(
            z3.simplify(z3.Or(obj.is_int, obj.is_bool))
        ):
            type_name = "int"
        elif object_type == "float":
            type_name = "float"
        elif object_type in {"file", "TextIO", "BinaryIO"}:
            type_name = "file"
        elif z3.is_true(z3.simplify(obj.is_dict)):
            type_name = "dict"
        elif z3.is_true(z3.simplify(obj.is_list)):
            type_name = "list"
        elif z3.is_true(z3.simplify(obj.is_str)):
            type_name = "str"
        elif isinstance(obj.value, bytes):
            type_name = "bytes"
        elif isinstance(obj.value, set) or getattr(obj, "_type", "") == "set":
            type_name = "set"
    else:
        obj_name = getattr(obj, "name", "") or getattr(obj, "_name", "")
        if "set" in obj_name.lower() or getattr(obj, "_type", "") == "set":
            type_name = "set"

    if type_name != "unknown":
        model_name = f"{type_name}.{attr_name}"
        if resolve_model(model_name):
            res_val = _modeled_attribute_carrier(f"{getattr(obj, 'name', 'obj')}.{attr_name}")
            res_val.model_name = model_name
            state = state.push(res_val)
            if push_null:
                state = state.push(obj)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
    if isinstance(obj, SymbolicValue):
        none_check: list[z3.BoolRef] = []
        if can_constrain_receiver_non_none_without_solver(obj):
            state = state.add_constraint(z3.Not(obj.is_none))
        else:
            none_check = [*state.path_constraints, obj.is_none]
            if not path_is_sat(none_check):
                none_check = []
        if none_check:
            must_be_none = not path_is_sat([*state.path_constraints, z3.Not(obj.is_none)])
            is_unconstrained_var = (
                z3.is_const(obj.is_none) and obj.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
            )

            if must_be_none or not is_unconstrained_var:
                if must_be_none:
                    state = state.add_constraint(z3.Not(obj.is_none))

            state = state.add_constraint(z3.Not(obj.is_none))

    if result_val is None:
        result_val, type_constraint = SymbolicValue.symbolic(
            f"{getattr(obj, 'name', 'obj')}.{attr_name}"
        )
        result_val.model_name = f"{type_name}.{attr_name}"
        if isinstance(obj_state, (dict, CowDict)):
            obj_state[attr_name] = result_val
        state = state.add_constraint(type_constraint)

        state = state.add_constraint(z3.Not(result_val.is_none))

    state = state.push(as_stack_value(result_val))
    if push_null:
        state = state.push(
            as_stack_value(obj)
            if isinstance(obj, SymbolicObject) or type_name != "unknown"
            else SymbolicNone()
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _modeled_attribute_carrier(name: str) -> SymbolicValue:
    """Return a definite model-call token without scalar type-tag constraints."""
    return SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
    )


def _load_path_string_attribute(
    obj: SymbolicString, attr_name: str
) -> tuple[StackValue, z3.BoolRef] | None:
    """Build bounded pathlib property values for modeled path-like strings."""
    if not obj.name.startswith(PATH_STRING_PREFIXES):
        return None
    if attr_name == "suffixes":
        return SymbolicList.symbolic(f"{obj.name}.suffixes", element_type="str")
    if attr_name in PATH_STRING_STRING_PROPERTIES:
        return SymbolicString.symbolic(f"{obj.name}.{attr_name}")
    return None


def _attribute_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str,
) -> OpcodeResult:
    """Jump to an ``AttributeError`` handler or emit a definite attribute-error issue."""
    exc = AttributeError(message)
    modeled_exc = SymbolicException.concrete(AttributeError, str(exc), raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=IssueKind.ATTRIBUTE_ERROR,
        message=f"Possible AttributeError: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _none_attribute_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    attr_name: str,
) -> OpcodeResult:
    """Route missing ``None`` attributes through handlers or emit a null-deref issue."""
    exc = AttributeError(f"'NoneType' object has no attribute '{attr_name}'")
    modeled_exc = SymbolicException.concrete(AttributeError, str(exc), raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=IssueKind.NULL_DEREFERENCE,
        message=f"Attribute access '{attr_name}' on None",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
