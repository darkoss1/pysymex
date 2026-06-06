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

"""Class-body method and descriptor helpers for common function opcodes."""

from __future__ import annotations

import dis
import types
from collections.abc import Mapping
from typing import cast

from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.functions.classes.concrete import (
    register_concrete_type_members,
)
from pysymex.execution.opcodes.common.functions.classes.function_metadata import (
    class_body_function_payload,
)
from pysymex.execution.opcodes.common.functions.classes.property_markers import (
    property_marker_deleter,
    property_marker_getter,
    property_marker_setter,
)
from pysymex.execution.opcodes.common.functions.classes.slots import (
    extract_literal_slots as _extract_literal_slots,
)

_CLASS_BODY_DECORATOR_NOOPS = frozenset({"CACHE", "PRECALL"})


def _class_body_effective_instructions(class_body: types.CodeType) -> list[dis.Instruction]:
    """Return class-body bytecode with decorator no-op opcodes removed."""
    return [
        instr
        for instr in cached_get_instructions(class_body)
        if instr.opname not in _CLASS_BODY_DECORATOR_NOOPS
    ]


def _last_make_function_before(
    instructions: list[dis.Instruction],
    store_index: int,
) -> int | None:
    """Find the ``MAKE_FUNCTION`` index preceding a class-body ``STORE_*``."""
    if store_index < 1 or instructions[store_index - 1].opname != "CALL":
        return None
    for index in range(store_index - 2, -1, -1):
        instr = instructions[index]
        if instr.opname == "MAKE_FUNCTION":
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def _code_const_before_make_function(
    instructions: list[dis.Instruction],
    make_index: int,
) -> int | None:
    """Locate the ``LOAD_CONST`` code object feeding a ``MAKE_FUNCTION``."""
    for index in range(make_index - 1, -1, -1):
        instr = instructions[index]
        if instr.opname == "LOAD_CONST" and isinstance(instr.argval, types.CodeType):
            return index
        if instr.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
            return None
    return None


def _previous_class_body_store_index(
    instructions: list[dis.Instruction],
    before_index: int,
) -> int:
    """Return the index of the previous ``STORE_NAME``/``STORE_GLOBAL`` in a body."""
    for index in range(before_index - 1, -1, -1):
        if instructions[index].opname in {"STORE_NAME", "STORE_GLOBAL"}:
            return index
    return -1


def _property_assignment_code(
    instructions: list[dis.Instruction],
    store_index: int,
) -> types.CodeType | None:
    """Return accessor ``CodeType`` for a property assignment at *store_index*."""
    make_index = _last_make_function_before(instructions, store_index)
    if make_index is None:
        return None
    code_index = _code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return None
    code = instructions[code_index].argval
    return code if isinstance(code, types.CodeType) else None


def _is_property_getter_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
    allow_cached_property: bool = False,
) -> bool:
    """Return whether a store names a ``property`` or trusted ``cached_property``."""
    code = _property_assignment_code(instructions, store_index)
    if code is None:
        return False
    make_index = _last_make_function_before(instructions, store_index)
    assert make_index is not None
    code_index = _code_const_before_make_function(instructions, make_index)
    assert code_index is not None
    boundary = _previous_class_body_store_index(instructions, code_index)
    search = instructions[boundary + 1 : code_index]
    for index, instr in enumerate(search):
        if instr.opname == "LOAD_NAME" and instr.argval == "property":
            return True
        if (
            allow_cached_property
            and index + 1 < len(search)
            and instr.opname == "LOAD_NAME"
            and instr.argval == "functools"
            and search[index + 1].opname == "LOAD_ATTR"
            and search[index + 1].argval == "cached_property"
        ):
            return True
    return False


def _is_property_accessor_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
    property_name: str,
    accessor_name: str,
) -> bool:
    """Return whether a store assigns a property ``setter`` or ``deleter``."""
    make_index = _last_make_function_before(instructions, store_index)
    if make_index is None:
        return False
    code_index = _code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return False
    boundary = _previous_class_body_store_index(instructions, code_index)
    search = instructions[boundary + 1 : code_index]
    for index, instr in enumerate(search[:-1]):
        next_instr = search[index + 1]
        if (
            instr.opname == "LOAD_NAME"
            and instr.argval == property_name
            and next_instr.opname == "LOAD_ATTR"
            and next_instr.argval == accessor_name
        ):
            return True
    return False


def _decorated_method_kind(
    instructions: list[dis.Instruction],
    method_name: str,
) -> str | None:
    """Classify ``staticmethod``, ``classmethod``, or ``abstractmethod`` decorations."""
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or instr.argval != method_name:
            continue
        make_index = _last_make_function_before(instructions, index)
        if make_index is None:
            continue
        code_index = _code_const_before_make_function(instructions, make_index)
        if code_index is None:
            continue
        code_obj = instructions[code_index].argval
        if not isinstance(code_obj, types.CodeType) or code_obj.co_name != method_name:
            continue
        boundary = _previous_class_body_store_index(instructions, code_index)
        decorators = {
            str(decorator.argval)
            for decorator in instructions[boundary + 1 : code_index]
            if decorator.opname == "LOAD_NAME" and isinstance(decorator.argval, str)
        }
        if "staticmethod" in decorators:
            return "static"
        if "classmethod" in decorators:
            return "class"
        if "abstractmethod" in decorators:
            return "abstract"
    return None


def _register_property_descriptors_with_closure(
    modeled_cls: object,
    class_body: types.CodeType,
    *,
    closure_by_name: Mapping[str, object] | None,
) -> None:
    """Register property descriptors and retain class-body closure cells."""
    try:
        from pysymex.models.objects import SymbolicClass
    except ImportError:
        return
    if not isinstance(modeled_cls, SymbolicClass):
        return
    allow_cached_property = getattr(modeled_cls, "_pysymex_trusted_cached_property", False) is True
    instructions = _class_body_effective_instructions(class_body)
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or not isinstance(instr.argval, str):
            continue
        property_name = instr.argval
        accessor_code = _property_assignment_code(instructions, index)
        if _is_property_getter_assignment(instructions, index, allow_cached_property):
            modeled_cls.add_property(
                property_name,
                fget=property_marker_getter,
                getter_code=class_body_function_payload(
                    instructions,
                    accessor_code,
                    closure_by_name,
                ),
            )
        elif _is_property_accessor_assignment(instructions, index, property_name, "setter"):
            existing = modeled_cls.properties.get(property_name)
            fget = getattr(existing, "fget", None) or property_marker_getter
            modeled_cls.add_property(
                property_name,
                fget=fget,
                fset=property_marker_setter,
                getter_code=getattr(existing, "getter_code", None),
                setter_code=class_body_function_payload(
                    instructions,
                    accessor_code,
                    closure_by_name,
                ),
                deleter_code=getattr(existing, "deleter_code", None),
            )
        elif _is_property_accessor_assignment(instructions, index, property_name, "deleter"):
            existing = modeled_cls.properties.get(property_name)
            fget = getattr(existing, "fget", None) or property_marker_getter
            modeled_cls.add_property(
                property_name,
                fget=fget,
                fset=getattr(existing, "fset", None),
                fdel=property_marker_deleter,
                getter_code=getattr(existing, "getter_code", None),
                setter_code=getattr(existing, "setter_code", None),
                deleter_code=class_body_function_payload(
                    instructions,
                    accessor_code,
                    closure_by_name,
                ),
            )


def register_class_body_methods(
    modeled_cls: object,
    class_body: types.CodeType | type,
    *,
    closure_by_name: Mapping[str, object] | None = None,
) -> None:
    """Populate modeled methods, slots, and properties from class-body bytecode."""
    try:
        from pysymex.models.objects import MethodType, SymbolicClass, extract_init_params
    except ImportError:
        return
    if not isinstance(modeled_cls, SymbolicClass):
        return

    if isinstance(class_body, type):
        register_concrete_type_members(modeled_cls, class_body)
        return

    slots = _extract_literal_slots(class_body)
    if slots is not None:
        modeled_cls.slots = slots
    instructions = _class_body_effective_instructions(class_body)
    for const in class_body.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        method_name = const.co_name
        if method_name in {"<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>"}:
            continue
        method_kind = _decorated_method_kind(instructions, method_name)
        method_type = MethodType.INSTANCE
        if method_kind == "static":
            method_type = MethodType.STATIC
        elif method_kind == "class":
            method_type = MethodType.CLASS
        elif method_kind == "abstract":
            method_type = MethodType.ABSTRACT
        method_func = class_body_function_payload(instructions, const, closure_by_name)
        modeled_cls.add_method(
            method_name,
            method_func,
            method_type=method_type,
            parameters=list(const.co_varnames[: const.co_argcount]),
        )
        if method_name == "__init__":
            modeled_cls.set_init_params(extract_init_params(const))
    _register_property_descriptors_with_closure(
        modeled_cls,
        class_body,
        closure_by_name=closure_by_name,
    )


def _modeled_class_from_symbolic_class_value(obj: SymbolicValue) -> object | None:
    """Resolve a modeled class registry entry from a symbolic type value."""
    from pysymex.execution.opcodes.common.functions.classes.registration import (
        modeled_class_from_value,
    )

    return modeled_class_from_value(obj)


def class_level_modeled_attribute(obj: SymbolicValue, attr_name: str) -> tuple[object, bool]:
    """Look up class methods or class variables on a symbolic type operand."""
    modeled_cls = _modeled_class_from_symbolic_class_value(obj)
    if modeled_cls is None:
        return None, False
    get_method = getattr(modeled_cls, "get_method", None)
    if callable(get_method):
        method = get_method(attr_name)
        if method is not None:
            method_type = getattr(method, "method_type", None)
            if getattr(method_type, "name", "") == "CLASS":
                bind_to_class = getattr(method, "bind_to_class", None)
                if callable(bind_to_class):
                    return bind_to_class(obj), True
            return method, True
    class_vars = getattr(modeled_cls, "class_vars", {})
    if isinstance(class_vars, dict) and attr_name in class_vars:
        typed_class_vars = cast("dict[str, object]", class_vars)
        return typed_class_vars[attr_name], True
    return None, False
