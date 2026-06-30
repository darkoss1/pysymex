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

"""Property descriptor registration from class-body bytecode."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.properties import (
    property_marker_deleter,
    property_marker_getter,
    property_marker_setter,
)
from pysymex._internal.execution.opcodes.common.functions.classes.descriptors.bytecode import (
    class_body_effective_instructions,
    code_const_before_make_function,
    last_make_function_before,
    previous_class_body_store_index,
)
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.payload import (
    class_body_function_payload,
)

if TYPE_CHECKING:
    import dis
    from collections.abc import Mapping


def property_assignment_code(
    instructions: list[dis.Instruction],
    store_index: int,
) -> types.CodeType | None:
    """Return accessor ``CodeType`` for a property assignment at *store_index*."""
    make_index = last_make_function_before(instructions, store_index)
    if make_index is None:
        return None
    code_index = code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return None
    code = instructions[code_index].argval
    return code if isinstance(code, types.CodeType) else None


def is_property_getter_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
    allow_cached_property: bool = False,
) -> bool:
    """Return whether a store names a ``property`` or trusted ``cached_property``."""
    code = property_assignment_code(instructions, store_index)
    if code is None:
        return False
    make_index = last_make_function_before(instructions, store_index)
    assert make_index is not None
    code_index = code_const_before_make_function(instructions, make_index)
    assert code_index is not None
    boundary = previous_class_body_store_index(instructions, code_index)
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


def is_property_accessor_assignment(
    instructions: list[dis.Instruction],
    store_index: int,
    property_name: str,
    accessor_name: str,
) -> bool:
    """Return whether a store assigns a property ``setter`` or ``deleter``."""
    make_index = last_make_function_before(instructions, store_index)
    if make_index is None:
        return False
    code_index = code_const_before_make_function(instructions, make_index)
    if code_index is None:
        return False
    boundary = previous_class_body_store_index(instructions, code_index)
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


def bind_property_descriptors_to_closure(
    modeled_cls: object,
    class_body: types.CodeType,
    *,
    closure_by_name: Mapping[str, object] | None,
    contract_decorator_names: frozenset[str],
) -> None:
    """Register property descriptors and retain class-body closure cells."""
    try:
        from pysymex._internal.core.classes.classes import SymbolicClass
    except ImportError:
        return
    if not isinstance(modeled_cls, SymbolicClass):
        return
    allow_cached_property = getattr(modeled_cls, "_pysymex_trusted_cached_property", False) is True
    instructions = class_body_effective_instructions(class_body)
    for index, instr in enumerate(instructions):
        if instr.opname not in {"STORE_NAME", "STORE_GLOBAL"} or not isinstance(instr.argval, str):
            continue
        property_name = instr.argval
        accessor_code = property_assignment_code(instructions, index)
        if is_property_getter_assignment(instructions, index, allow_cached_property):
            modeled_cls.add_property(
                property_name,
                fget=property_marker_getter,
                getter_code=class_body_function_payload(
                    instructions,
                    accessor_code,
                    closure_by_name,
                    contract_decorator_names,
                ),
            )
        elif is_property_accessor_assignment(instructions, index, property_name, "setter"):
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
                    contract_decorator_names,
                ),
                deleter_code=getattr(existing, "deleter_code", None),
            )
        elif is_property_accessor_assignment(instructions, index, property_name, "deleter"):
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
                    contract_decorator_names,
                ),
            )
