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

"""Symbolic carrier creation for initial execution inputs."""

from __future__ import annotations

from collections.abc import Mapping
import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.identity.addressing import next_address
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
from pysymex.execution.initial_state.hints import parse_instance_type_hint
from pysymex.execution.initial_state.types import SymbolicCreatedValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue

__all__ = ["SymbolicInputFactory", "create_symbolic_instance_for_class"]


class SymbolicInputFactory:
    """Create symbolic input carriers and stage heap-backed container values."""

    def __init__(self) -> None:
        self._temp_memory: dict[int, StackValue] = {}

    def flush_temp_memory(self, state: VMState) -> VMState:
        """Store staged heap objects into *state* and clear the staging area."""
        for address, value in self._temp_memory.items():
            state = state.store_heap(address, value)
        self._temp_memory = {}
        return state

    def create_symbolic_for_type(
        self, name: str, type_hint: str
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value and its type constraint for an execution hint."""
        type_hint = type_hint.lower()

        if name == "self" and type_hint == "any":
            type_hint = "object"

        if type_hint.startswith(("optional:", "nullable:")):
            _prefix, _separator, inner_type_hint = type_hint.partition(":")
            return self.create_nullable_symbolic_for_type(name, inner_type_hint or "any")

        if type_hint.startswith(("int", "integer")):
            value_int, constraint_int = SymbolicValue.symbolic_int(name)
            return cast("SymbolicCreatedValue", value_int), constraint_int
        if type_hint.startswith(("float", "real")):
            return AdvancedSymbolicFloat(name), Z3_TRUE
        if type_hint.startswith(("str", "string")):
            value_str, constraint_str = SymbolicString.symbolic(name)
            return cast("SymbolicCreatedValue", value_str), constraint_str
        if type_hint.startswith("bytes"):
            return SymbolicBytes.symbolic(name), Z3_TRUE
        if type_hint.startswith("bytearray"):
            value_bytes, constraint_bytes = SymbolicList.symbolic(name, element_type="byte")
            setattr(value_bytes, "_type", "bytearray")
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, get_int_val(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_bytes)
            return cast("SymbolicCreatedValue", sym_obj), constraint_bytes
        if type_hint.startswith(("list", "array", "tuple")):
            value_list, constraint_list = SymbolicList.symbolic(name)
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, get_int_val(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_list)
            return cast("SymbolicCreatedValue", sym_obj), constraint_list
        if type_hint.startswith(("bool", "boolean")):
            value_bool, constraint_bool = SymbolicValue.symbolic_bool(name)
            return cast("SymbolicCreatedValue", value_bool), constraint_bool
        if type_hint.startswith(("path", "pathlib.path")):
            value_path, constraint_path = SymbolicValue.symbolic_path(name)
            return cast("SymbolicCreatedValue", value_path), constraint_path
        if type_hint.startswith(("dict", "mapping", "kwargs")):
            value_dict, constraint_dict = SymbolicDict.symbolic(name)
            if "nested" in type_hint:
                setattr(value_dict, "_value_type", "dict")
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, get_int_val(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_dict)
            return cast("SymbolicCreatedValue", sym_obj), constraint_dict
        if type_hint == "object":
            id_suffix = next_address()
            z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
            sym_val = SymbolicObject(
                _name=name,
                address=id_suffix,
                z3_addr=z3_addr,
                potential_addresses={id_suffix},
            )
            return sym_val, z3_addr != 0
        if type_hint in {"any", "nullable", "optional"}:
            sym_val, constraint = SymbolicValue.symbolic(name)
            return cast("SymbolicCreatedValue", sym_val), constraint

        sym_val, constraint = SymbolicValue.symbolic(name)
        return cast("SymbolicCreatedValue", sym_val), z3.And(constraint, z3.Not(sym_val.is_none))

    def create_nullable_symbolic_for_type(
        self, name: str, inner_type_hint: str
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value constrained to ``None`` or one non-null type."""
        sym_val, constraint = SymbolicValue.symbolic(name)
        type_hint = inner_type_hint.lower()
        type_branch: z3.BoolRef | None = None
        if type_hint.startswith(("int", "integer")):
            type_branch = sym_val.is_int
        elif type_hint.startswith(("float", "real")):
            type_branch = sym_val.is_float
        elif type_hint.startswith(("str", "string")):
            type_branch = sym_val.is_str
        elif type_hint.startswith(("bool", "boolean")):
            type_branch = sym_val.is_bool
        elif type_hint.startswith(("path", "pathlib.path")):
            type_branch = sym_val.is_path
        elif type_hint.startswith(("list", "array", "tuple")):
            type_branch = sym_val.is_list
        elif type_hint.startswith(("dict", "mapping", "kwargs")):
            type_branch = sym_val.is_dict
        elif type_hint == "object":
            type_branch = sym_val.is_obj

        if type_branch is None:
            return cast("SymbolicCreatedValue", sym_val), constraint

        nullable_constraint = z3.And(constraint, z3.Or(sym_val.is_none, type_branch))
        return cast("SymbolicCreatedValue", sym_val), nullable_constraint

    def create_symbolic_for_context_type(
        self,
        name: str,
        type_hint: str,
        initial_globals: Mapping[str, StackValue] | None,
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value, including modeled ``instance:Class|...`` hints."""
        if not type_hint.lower().startswith("instance:"):
            return self.create_symbolic_for_type(name, type_hint)
        class_name, init_type_hints = parse_instance_type_hint(type_hint)
        created = create_symbolic_instance_for_class(
            name, class_name, init_type_hints, initial_globals
        )
        if created is not None:
            return created
        return self.create_symbolic_for_type(name, "object")


def create_symbolic_instance_for_class(
    name: str,
    class_name: str,
    init_type_hints: dict[str, str],
    initial_globals: Mapping[str, StackValue] | None,
) -> tuple[SymbolicCreatedValue, z3.BoolRef] | None:
    """Instantiate a modeled class from globals when registry metadata is available."""
    if not initial_globals:
        return None
    class_obj = initial_globals.get(class_name)
    if not isinstance(class_obj, SymbolicValue):
        return None
    class_body = getattr(class_obj, "_modeled_object", None)
    class_init_hints = getattr(class_obj, "_pysymex_init_type_hints", None)
    if isinstance(class_init_hints, dict):
        typed_init_hints = cast("dict[object, object]", class_init_hints)
        for key, value in typed_init_hints.items():
            if isinstance(key, str) and isinstance(value, str):
                init_type_hints.setdefault(key, value.lower())
    try:
        from pysymex.models.objects import class_registry
        from pysymex.execution.opcodes.common.functions.classes import (
            apply_straight_line_init_assignments,
            modeled_class_from_value,
        )

        modeled_cls = None
        if isinstance(class_body, types.CodeType):
            modeled_cls = modeled_class_from_value(class_obj)
        if modeled_cls is None:
            modeled_cls = class_registry.get_class(class_name)
        if modeled_cls is None:
            return None
        for param in getattr(modeled_cls, "init_params", []):
            param_name = getattr(param, "name", None)
            if isinstance(param_name, str) and param_name in init_type_hints:
                setattr(param, "type_hint", init_type_hints[param_name])

        instance = class_registry.instantiate(modeled_cls)
        apply_straight_line_init_assignments(modeled_cls, instance, [], {})
    except (ImportError, AttributeError, TypeError, ValueError, z3.Z3Exception):
        return None

    result = SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type=class_name,
    )
    result.attach_modeled_object(instance)
    return cast("SymbolicCreatedValue", result), Z3_TRUE
