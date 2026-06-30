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

"""Symbolic object-address carrier used for heap-backed object references."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def _empty_potential_addresses() -> set[int]:
    """Create a typed empty candidate-address set."""
    return set()


@dataclass
class SymbolicObject(SymbolicType):
    """Object-reference value represented by an integer address expression.

    Attributes:
        _name: Debugging name.
        address: Known concrete address or ``-1`` when not singular.
        z3_addr: Z3 integer representing the address.
        potential_addresses: Concrete candidate metadata accumulated by merges.

    Limitations:
        The candidate-address set is metadata; this class does not itself add
        constraints requiring ``z3_addr`` to equal one of those candidates.

    """

    _name: str
    address: int
    z3_addr: z3.ArithRef
    potential_addresses: set[int] = field(default_factory=_empty_potential_addresses)
    _h_active: bool = field(default=False)
    model_name: str | None = field(default=None, compare=False)

    __hash__ = object.__hash__

    def __post_init__(self) -> None:
        """Initialize candidate metadata for a known concrete address."""
        if not self.potential_addresses and self.address != -1:
            self.potential_addresses = {self.address}
        if self._name:
            ln = self._name.lower()
            if ln in ("self", "cls") or ln.startswith(("self_", "cls_")):
                self._h_active = True

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic object."""
        return self._name

    @staticmethod
    def resolve(value: object, state: VMState) -> object:
        """Resolve a heap-backed handle, otherwise return the input value."""
        if isinstance(value, SymbolicObject) and value.address != -1:
            resolved = state.memory.get(value.address)
            if resolved is not None:
                return resolved
        return value

    @property
    def is_int(self) -> z3.BoolRef:
        """Property returning the is_int."""
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        """Property returning the is_bool."""
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        """Property returning the is_str."""
        return Z3_FALSE

    @property
    def is_none(self) -> z3.BoolRef:
        """Property returning the is_none."""
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        """Property returning the is_obj."""
        return Z3_TRUE

    @property
    def is_path(self) -> z3.BoolRef:
        """Property returning the is_path."""
        return Z3_FALSE

    @property
    def is_list(self) -> z3.BoolRef:
        """Property returning the is_list."""
        return Z3_FALSE

    @property
    def is_dict(self) -> z3.BoolRef:
        """Property returning the is_dict."""
        return Z3_FALSE

    @property
    def is_bytes(self) -> z3.BoolRef:
        """Return the invariant that objects are not bytes carriers."""
        return Z3_FALSE

    @property
    def is_tuple(self) -> z3.BoolRef:
        """Return the invariant that objects are not tuple carriers."""
        return Z3_FALSE

    @property
    def is_set(self) -> z3.BoolRef:
        """Return the invariant that objects are not set carriers."""
        return Z3_FALSE

    def to_z3(self) -> z3.ExprRef:
        """Return the object address expression."""
        return self.z3_addr

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the object address is nonzero."""
        if self.address >= 0:
            return Z3_TRUE if self.address != 0 else Z3_FALSE
        if z3.eq(self.z3_addr, Z3_ZERO):
            return Z3_FALSE
        if z3.is_int_value(self.z3_addr):
            return Z3_TRUE
        return self.z3_addr != 0

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the object address is null."""
        if self.address >= 0:
            return Z3_FALSE if self.address != 0 else Z3_TRUE
        if z3.eq(self.z3_addr, Z3_ZERO):
            return Z3_TRUE
        if z3.is_int_value(self.z3_addr):
            return Z3_FALSE
        return self.z3_addr == 0

    @staticmethod
    def symbolic(name: str, address: int) -> tuple[SymbolicObject, z3.BoolRef]:
        """Create a fixed-address object or unconstrained address expression.

        Notes:
            The returned constraint is tautological, including for an
            unconstrained negative-address request.

        """
        if address >= 0:
            z3_addr = ConstraintValues.int(address)
            constraint = Z3_TRUE
        else:
            z3_addr = z3.Int(f"{name}_addr")
            constraint = Z3_TRUE
        return SymbolicObject(name, address, z3_addr, {address}), constraint

    @staticmethod
    def from_const(value: object) -> SymbolicObject:
        """Represent a concrete host object using ``id(value)`` as address metadata."""
        addr = id(value)
        return SymbolicObject(f"obj_{addr}", addr, ConstraintValues.int(addr), {addr})

    def _symbolic_eq(self, other: object) -> SymbolicValue:
        """Return address equality against an object or the null address for ``None``."""
        if isinstance(other, SymbolicObject):
            cond = self.z3_addr == other.z3_addr
            other_name = other.name
        elif isinstance(other, SymbolicNoneType):
            cond = self.z3_addr == 0
            other_name = "None"
        else:
            cond = Z3_FALSE
            other_name = str(type(other).__name__)

        return SymbolicValue(
            _name=f"({self._name}=={other_name})",
            z3_int=z3.If(cond, ConstraintValues.int(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def _symbolic_ne(self, other: object) -> SymbolicValue:
        """Return address inequality against an object or the null address for ``None``."""
        eq_result = self._symbolic_eq(other)
        neq_cond = z3.Not(eq_result.z3_bool)
        return SymbolicValue(
            _name=f"({self._name}!={getattr(other, 'name', str(type(other).__name__))})",
            z3_int=z3.If(neq_cond, ConstraintValues.int(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=neq_cond,
            is_bool=Z3_TRUE,
            is_str=Z3_FALSE,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    if TYPE_CHECKING:

        def __eq__(self, other: object) -> bool: ...

        def __ne__(self, other: object) -> bool: ...

    else:

        def __eq__(self, other: object) -> SymbolicValue:
            return self._symbolic_eq(other)

        def __ne__(self, other: object) -> SymbolicValue:
            return self._symbolic_ne(other)

    def __repr__(self) -> str:
        """Return the diagnostic representation for this object carrier."""
        return f"SymbolicObject({self._name}, addr={self.address})"

    def conditional_merge(
        self,
        other: object,
        condition: z3.BoolRef,
    ) -> SymbolicObject | SymbolicValue:
        """Return a condition-selected object address or heterogeneous value.

        Notes:
            Object/object merges union candidate-address metadata; this does
            not itself constrain the selected address to that metadata set.

        """
        if isinstance(other, SymbolicNoneType):
            zero_val = Z3_ZERO
            are_addr_zero = self.z3_addr is zero_val or Z3ExpressionOps.safe_eq(
                self.z3_addr,
                zero_val,
            )
            if are_addr_zero:
                return self
            new_addr = z3.If(condition, self.z3_addr, zero_val)
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, None)",
                address=-1,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.copy(),
            )
        if isinstance(other, SymbolicObject):
            if self is other:
                return self

            are_addr_equal = self.z3_addr is other.z3_addr or Z3ExpressionOps.safe_eq(
                self.z3_addr,
                other.z3_addr,
            )
            new_addr = (
                self.z3_addr if are_addr_equal else z3.If(condition, self.z3_addr, other.z3_addr)
            )
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, {other.name})",
                address=-1 if self.address != other.address else self.address,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.union(other.potential_addresses),
            )
        val_self = SymbolicValue.from_specialized(self)
        return val_self.conditional_merge(other, condition)

    def hash_value(self) -> int:
        """Return a structural hash over address expression and candidate metadata."""
        h = hash(self.address)
        h = (h * 31) ^ self.z3_addr.hash()
        if self.potential_addresses:
            h = (h * 31) ^ hash(frozenset(self.potential_addresses))
        return h

    @staticmethod
    def resolve_runtime_container(container: object, state: VMState) -> object:
        """Load heap-backed symbolic objects before container mutation."""
        if isinstance(container, SymbolicObject):
            return state.load_heap(container.address, container)

        if isinstance(container, SymbolicValue):
            modeled_object = getattr(container, "_modeled_object", None)
            if isinstance(modeled_object, SymbolicObject):
                return state.load_heap(modeled_object.address, modeled_object)
            if modeled_object is not None:
                return modeled_object
            const_value = container.value
            if const_value is not None:
                return const_value

        return container

    @staticmethod
    def resolve_stack_value(state: VMState, value: object) -> object:
        """Replace heap handles with their stored stack value when present."""
        resolved = SymbolicObject.resolve(value, state)
        if resolved is value:
            return value
        from pysymex._internal.core.types.stack_coercion import StackValuePolicy

        return StackValuePolicy.coerce(resolved)
