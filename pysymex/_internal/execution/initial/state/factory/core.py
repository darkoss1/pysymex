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

"""General symbolic input carrier creation and heap staging."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.hints import (
    SymbolicHintKind,
    canonicalize_symbolic_type_hint,
    parse_fixed_tuple_type_hint,
    symbolic_hint_kind,
)
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.initial.state.factory.instances import (
    create_symbolic_instance_for_class,
)
from pysymex._internal.execution.initial.state.factory.nullable import (
    create_nullable_symbolic_for_type as create_nullable_symbolic_value_for_type,
)
from pysymex._internal.execution.initial.state.hints import parse_instance_type_hint

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.initial.state.types import SymbolicCreatedValue
    from pysymex._internal.typing.protocols import StackValue


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
        self,
        name: str,
        type_hint: str,
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value and its type constraint for an execution hint."""
        type_hint = canonicalize_symbolic_type_hint(type_hint)

        if name == "self" and type_hint == "any":
            type_hint = "object"

        if type_hint.startswith("optional:"):
            _prefix, _separator, inner_type_hint = type_hint.partition(":")
            return self.create_nullable_symbolic_for_type(name, inner_type_hint or "any")

        kind = symbolic_hint_kind(type_hint)

        if kind == SymbolicHintKind.INT:
            value_int, constraint_int = SymbolicValue.symbolic_int(name)
            return cast("SymbolicCreatedValue", value_int), constraint_int
        if kind == SymbolicHintKind.FLOAT:
            return SymbolicFloat(name), Z3_TRUE
        if kind == SymbolicHintKind.STR:
            value_str, constraint_str = SymbolicString.symbolic(name)
            return cast("SymbolicCreatedValue", value_str), constraint_str
        if kind == SymbolicHintKind.BYTES:
            return SymbolicBytes.symbolic(name), Z3_TRUE
        if kind == SymbolicHintKind.BYTEARRAY:
            value_bytes, constraint_bytes = SymbolicList.symbolic(name, element_type="byte")
            value_bytes.set_runtime_type("bytearray")
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, ConstraintValues.int(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_bytes)
            return cast("SymbolicCreatedValue", sym_obj), constraint_bytes
        fixed_tuple_types = parse_fixed_tuple_type_hint(type_hint)
        if fixed_tuple_types is not None:
            elements: list[SymbolicCreatedValue] = []
            constraints: list[z3.BoolRef] = []
            for index, element_type in enumerate(fixed_tuple_types):
                element, constraint = self.create_symbolic_for_type(
                    f"{name}[{index}]",
                    element_type,
                )
                elements.append(element)
                constraints.append(constraint)
            tuple_constraint = z3.And(*constraints) if constraints else Z3_TRUE
            return SymbolicTuple.from_elements(*elements), tuple_constraint
        if kind in {SymbolicHintKind.LIST, SymbolicHintKind.TUPLE}:
            value_list, constraint_list = SymbolicList.symbolic(name)
            if kind == SymbolicHintKind.TUPLE:
                value_list.set_runtime_type("tuple")
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, ConstraintValues.int(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_list)
            return cast("SymbolicCreatedValue", sym_obj), constraint_list
        if kind == SymbolicHintKind.BOOL:
            value_bool, constraint_bool = SymbolicValue.symbolic_bool(name)
            return cast("SymbolicCreatedValue", value_bool), constraint_bool
        if kind == SymbolicHintKind.PATH:
            value_path, constraint_path = SymbolicValue.symbolic_path(name)
            return cast("SymbolicCreatedValue", value_path), constraint_path
        if kind == SymbolicHintKind.DICT:
            value_dict, constraint_dict = SymbolicDict.symbolic(name)
            if "nested" in type_hint:
                value_dict.set_value_type("dict")
            addr = next_address()
            sym_obj = SymbolicObject(name, addr, ConstraintValues.int(addr), {addr})
            self._temp_memory[addr] = cast("StackValue", value_dict)
            return cast("SymbolicCreatedValue", sym_obj), constraint_dict
        if kind in {SymbolicHintKind.SET, SymbolicHintKind.FROZENSET}:
            value_set, constraint_set = SymbolicSet.symbolic(name)
            return value_set, constraint_set
        if kind == SymbolicHintKind.OBJECT:
            id_suffix = next_address()
            z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
            sym_val = SymbolicObject(
                _name=name,
                address=id_suffix,
                z3_addr=z3_addr,
                potential_addresses={id_suffix},
            )
            return sym_val, z3_addr != 0
        if kind == SymbolicHintKind.ANY:
            sym_val, constraint = SymbolicValue.symbolic(name)
            return cast("SymbolicCreatedValue", sym_val), constraint

        sym_val, constraint = SymbolicValue.symbolic(name)
        return cast("SymbolicCreatedValue", sym_val), z3.And(constraint, z3.Not(sym_val.is_none))

    def create_nullable_symbolic_for_type(
        self,
        name: str,
        inner_type_hint: str,
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value constrained to ``None`` or one non-null type."""
        return create_nullable_symbolic_value_for_type(name, inner_type_hint)

    def create_symbolic_for_context_type(
        self,
        name: str,
        type_hint: str,
        initial_globals: Mapping[str, object] | None,
    ) -> tuple[SymbolicCreatedValue, z3.BoolRef]:
        """Create a symbolic value, including modeled ``instance:Class|...`` hints."""
        if not type_hint.lower().startswith("instance:"):
            return self.create_symbolic_for_type(name, type_hint)
        class_name, init_type_hints = parse_instance_type_hint(type_hint)
        created = create_symbolic_instance_for_class(
            name,
            class_name,
            init_type_hints,
            initial_globals,
        )
        if created is not None:
            return created
        return self.create_symbolic_for_type(name, "object")
