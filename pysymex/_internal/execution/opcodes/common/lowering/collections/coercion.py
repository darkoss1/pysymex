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

"""Shared coercion helpers for symbolic collection lowering."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


class CollectionCoercionMixin:
    """Coerce stack values into collection lowering domains."""

    pc: int

    def _stringify(self, val: StackValue) -> SymbolicString:
        """Coerce a stack value to :class:`SymbolicString` for literal building."""
        if isinstance(val, SymbolicString):
            return val
        if isinstance(val, str):
            return SymbolicString.from_const(val)

        s_val = self._coerce_value(val)
        concrete = s_val.value
        if concrete is not None:
            return SymbolicString.from_const(str(concrete))

        affinity = s_val.affinity_type
        if affinity == "int":
            expr = s_val.z3_int
        elif affinity == "bool":
            expr = z3.If(s_val.z3_bool, Z3_ONE, Z3_ZERO)
        else:
            expr = z3.If(
                s_val.is_int,
                s_val.z3_int,
                z3.If(
                    s_val.is_bool,
                    z3.If(s_val.z3_bool, Z3_ONE, Z3_ZERO),
                    Z3_ZERO,
                ),
            )

        new_z3_str = z3.IntToStr(expr)
        return SymbolicString(
            _name=f"str({s_val.name})",
            _z3_str=new_z3_str,
            _z3_len=z3.Length(new_z3_str),
        )

    def _coerce_index(self, val: StackValue) -> SymbolicValue | None:
        """Return a symbolic integer index when *val* is indexable."""
        if isinstance(val, SymbolicValue):
            return val
        if isinstance(val, (int, bool)):
            return SymbolicValue.from_const(int(val))
        return None

    def _coerce_key(self, val: StackValue) -> SymbolicString | None:
        """Return a symbolic string key when *val* can name a mapping entry."""
        if isinstance(val, SymbolicString):
            return val
        if isinstance(val, tuple):
            return SymbolicString.from_const(str(cast("tuple[object, ...]", val)))
        if isinstance(val, SymbolicList) and getattr(val, "_type", None) == "tuple":
            concrete_items = val.concrete_items
            if concrete_items is not None:
                return SymbolicString.from_const(str(tuple(concrete_items)))
        if isinstance(val, frozenset):
            return SymbolicString.from_const(str(cast("frozenset[object]", val)))
        if val is None or isinstance(val, (str, int, bool, float, bytes)):
            return SymbolicString.from_const(str(val))
        if isinstance(val, SymbolicValue):
            return SymbolicString(_name=val.name, _unified=val)
        return None

    def _coerce_value(self, val: StackValue) -> SymbolicValue:
        """Wrap *val* as a :class:`SymbolicValue`."""
        if isinstance(val, SymbolicValue):
            return val
        return SymbolicValue.from_const(val)

    def element_reference(
        self,
        item: StackValue,
        address_by_identity: dict[int, int],
    ) -> tuple[StackValue, list[tuple[int, StackValue]]]:
        """Return a retained element value plus heap updates for nested containers."""
        if isinstance(item, SymbolicObject):
            return item, []
        if isinstance(item, (SymbolicList, SymbolicDict)):
            identity = id(item)
            existing_address = address_by_identity.get(identity)
            if existing_address is not None:
                return (
                    SymbolicObject(
                        f"collection_item_{existing_address}",
                        existing_address,
                        ConstraintValues.int(existing_address),
                        {existing_address},
                    ),
                    [],
                )
            addr = next_address()
            address_by_identity[identity] = addr
            return SymbolicObject(
                f"collection_item_{addr}",
                addr,
                ConstraintValues.int(addr),
                {addr},
            ), [(addr, item)]
        return item, []

    def _element_address_or_int(
        self,
        item: StackValue,
        address_by_identity: dict[int, int],
    ) -> tuple[z3.ArithRef, list[tuple[int, StackValue]]]:
        """Return heap address or Z3 int storage for a collection element."""
        retained_item, heap_updates = self.element_reference(item, address_by_identity)
        if isinstance(retained_item, SymbolicObject):
            return retained_item.z3_addr, heap_updates
        s_val = self._coerce_value(retained_item)
        return ContainerStorageOps.storage_int_expr(s_val.z3_int, f"collection_{self.pc}_elem"), []

    def _to_int_val(self, name: str, expr: z3.ArithRef) -> SymbolicValue:
        """Build a :class:`SymbolicValue` wrapper around an arbitrary Z3 integer."""
        return SymbolicValue(
            _name=name,
            z3_int=expr,
            is_int=Z3_TRUE,
            is_bool=Z3_FALSE,
            z3_bool=Z3_FALSE,
        )
