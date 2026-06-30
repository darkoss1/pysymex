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

"""Symbolic scalar and modeled-object attribute lookup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
    get_declared_class_descriptor,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.load.results import (
    attribute_error_result,
)
from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.methods import (
    dispatch_modeled_attribute_read,
    dispatch_modeled_descriptor_fallback,
    route_modeled_missing_attribute,
)
from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.lookup import (
    class_level_modeled_attribute,
)
from pysymex._internal.models.builtins.reflection.namespace import ModeledSuperProxy

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@runtime_checkable
class ModeledAttributeProvider(Protocol):
    """Runtime modeled objects that can resolve symbolic attribute reads."""

    def get_attribute(
        self,
        name: str,
        *,
        bound_instance: SymbolicValue,
    ) -> tuple[object, bool]:
        """Return a modeled attribute value and whether it was resolved."""
        ...


@dataclass(frozen=True)
class ValueAttributeLoad:
    """Result of symbolic scalar or modeled-object attribute lookup."""

    result_val: object | None
    type_name: str
    immediate_result: OpcodeResult | None = None


def _load_symbolic_value_intrinsic_attribute(
    obj: SymbolicValue,
    modeled_object: object,
    attr_name: str,
) -> ValueAttributeLoad | None:
    """Load generic-alias and retained exception attributes from symbolic values."""
    generic_alias_attr, generic_alias_found = _generic_alias_attribute(obj, attr_name)
    if generic_alias_found:
        return ValueAttributeLoad(
            result_val=coerce_call_stack_value(generic_alias_attr),
            type_name="unknown",
        )
    exception_attr, exception_attr_found = symbolic_exception_attribute(modeled_object, attr_name)
    if exception_attr_found:
        return ValueAttributeLoad(
            result_val=coerce_call_stack_value(exception_attr),
            type_name="unknown",
        )
    return None


def _dispatch_symbolic_value_descriptor_read(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    obj: SymbolicValue,
    modeled_object: object,
    attr_name: str,
    *,
    push_null: bool,
) -> ValueAttributeLoad | None:
    """Dispatch super proxy, modeled read, and declared class descriptor paths."""
    if isinstance(modeled_object, ModeledSuperProxy):
        from pysymex._internal.execution.opcodes.common.functions.super import (
            handle_modeled_super_proxy_attr,
        )

        return ValueAttributeLoad(
            result_val=None,
            type_name="unknown",
            immediate_result=handle_modeled_super_proxy_attr(
                instr,
                state,
                ctx,
                modeled_object,
                push_null=push_null,
            ),
        )
    for descriptor_result in (
        dispatch_modeled_attribute_read(state, ctx, obj, attr_name, push_null=push_null),
        get_declared_class_descriptor(state, ctx, obj, attr_name),
    ):
        if descriptor_result is not None:
            return ValueAttributeLoad(
                result_val=None,
                type_name="unknown",
                immediate_result=descriptor_result,
            )
    return None


def _load_modeled_object_dynamic_attribute(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    obj: SymbolicValue,
    modeled_object: object,
    attr_name: str,
    *,
    push_null: bool,
) -> ValueAttributeLoad | None:
    """Load modeled-object attributes or route descriptor/getattr fallbacks."""
    if not isinstance(modeled_object, ModeledAttributeProvider):
        return None
    attr_value, found = modeled_object.get_attribute(attr_name, bound_instance=obj)
    if found:
        return ValueAttributeLoad(
            result_val=coerce_call_stack_value(attr_value),
            type_name="unknown",
        )
    for dynamic_result in (
        dispatch_modeled_descriptor_fallback(state, ctx, obj, attr_name, push_null=push_null),
        route_modeled_missing_attribute(state, ctx, obj, attr_name, push_null=push_null),
    ):
        if dynamic_result is not None:
            return ValueAttributeLoad(
                result_val=None,
                type_name="unknown",
                immediate_result=dynamic_result,
            )
    return ValueAttributeLoad(
        result_val=None,
        type_name="unknown",
        immediate_result=attribute_error_result(
            instr,
            state,
            ctx,
            f"'{obj.name}' object has no attribute '{attr_name}'",
        ),
    )


def _symbolic_value_type_name(obj: SymbolicValue) -> str:
    """Infer the runtime family name for a symbolic scalar value."""
    object_type = obj.type_tag
    if obj.affinity_type not in {"", "unknown", "none"}:
        return obj.affinity_type
    if object_type in {"int", "bool"} or z3.is_true(simplify_expr(z3.Or(obj.is_int, obj.is_bool))):
        return "int"
    if object_type == "float":
        return "float"
    if object_type in {"file", "TextIO", "BinaryIO"}:
        return "file"
    if z3.is_true(simplify_expr(obj.is_dict)):
        return "dict"
    if z3.is_true(simplify_expr(obj.is_list)):
        return "list"
    if z3.is_true(simplify_expr(obj.is_str)):
        return "str"
    if isinstance(obj.value, bytes):
        return "bytes"
    if isinstance(obj.value, set) or getattr(obj, "_type", "") == "set":
        return "set"
    return "unknown"


def load_symbolic_value_attribute(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    obj: SymbolicValue,
    attr_name: str,
    *,
    push_null: bool,
) -> ValueAttributeLoad:
    """Resolve modeled hooks and scalar type names for symbolic values."""
    modeled_object = getattr(obj, "_modeled_object", None)
    intrinsic_load = _load_symbolic_value_intrinsic_attribute(obj, modeled_object, attr_name)
    if intrinsic_load is not None:
        return intrinsic_load

    descriptor_load = _dispatch_symbolic_value_descriptor_read(
        instr,
        state,
        ctx,
        obj,
        modeled_object,
        attr_name,
        push_null=push_null,
    )
    if descriptor_load is not None:
        return descriptor_load

    result_val: object | None = None
    class_attr_value, class_attr_found = class_level_modeled_attribute(obj, attr_name)
    if class_attr_found:
        result_val = coerce_call_stack_value(class_attr_value)

    if result_val is None:
        dynamic_load = _load_modeled_object_dynamic_attribute(
            instr,
            state,
            ctx,
            obj,
            modeled_object,
            attr_name,
            push_null=push_null,
        )
        if dynamic_load is not None:
            return dynamic_load

    return ValueAttributeLoad(
        result_val=result_val,
        type_name=_symbolic_value_type_name(obj),
    )


def _generic_alias_attribute(obj: SymbolicValue, attr_name: str) -> tuple[object | None, bool]:
    """Return modeled metadata for a local-class generic alias carrier."""
    if attr_name == "__origin__":
        origin = getattr(obj, "_pysymex_generic_alias_origin", None)
        if origin is not None:
            return origin, True
    if attr_name == "__args__":
        args = getattr(obj, "_pysymex_generic_alias_args", None)
        if isinstance(args, tuple):
            return cast("tuple[object, ...]", args), True
    if attr_name == "__parameters__":
        if getattr(obj, "_pysymex_generic_alias_origin", None) is not None:
            return (), True
    return None, False


def symbolic_exception_attribute(
    modeled_object: object,
    attr_name: str,
) -> tuple[object | None, bool]:
    """Return retained CPython exception attributes for modeled exceptions."""
    if not isinstance(modeled_object, SymbolicException):
        return None, False
    if attr_name == "args":
        return modeled_object.args, True
    if attr_name == "value" and modeled_object.type_name == "StopIteration":
        return modeled_object.value, True
    if attr_name == "exceptions" and _is_exception_group_type(modeled_object.exc_type):
        if len(modeled_object.args) == 2:
            members = modeled_object.args[1]
            if isinstance(members, list):
                return tuple(cast("list[object]", members)), True
            if isinstance(members, tuple):
                return cast("tuple[object, ...]", members), True
        return (), True
    return None, False


def _is_exception_group_type(exc_type: object) -> bool:
    """Return whether *exc_type* is a concrete exception-group class."""
    return isinstance(exc_type, type) and issubclass(exc_type, BaseExceptionGroup)
