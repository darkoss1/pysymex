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

"""Z3 Boolean-backed symbolic value used by numeric truthiness operations."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE

from ..base import SymbolicType, TypeTag, fresh_name


def _bool_truthiness(expr: z3.BoolRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for fixed Boolean expressions."""
    if z3.is_true(expr):
        return Z3_TRUE if truthy else Z3_FALSE
    if z3.is_false(expr):
        return Z3_FALSE if truthy else Z3_TRUE
    if truthy:
        return expr
    return z3.Not(expr)


@dataclass
class SymbolicBool(SymbolicType):
    """Boolean value represented directly by a Z3 ``Bool`` expression.

    Equality with :class:`SymbolicInt` follows Python's Boolean-as-integer
    convention by relating ``True`` to ``1`` and ``False`` to ``0``.
    """

    z3_bool: z3.BoolRef
    _name: str = field(default="")

    __hash__ = object.__hash__

    def hash_value(self) -> int:
        """Return the Z3 expression hash used in VM state summaries.

        Notes:
            Python ``__hash__`` remains identity-based for dictionary and set
            use. This structural value is not a feasibility or equivalence
            proof.
        """
        return self.z3_bool.hash()

    def __post_init__(self) -> None:
        """Assign a fresh Boolean name when construction did not provide one."""
        if not self._name:
            self._name = fresh_name("bool")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.BOOL

    @property
    def is_bool(self) -> z3.BoolRef:
        """Return the definite Boolean-type marker for this carrier."""
        return Z3_TRUE

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic Boolean."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 Boolean expression represented by this carrier."""
        return self.z3_bool

    def is_truthy(self) -> z3.BoolRef:
        """Return the represented Boolean as its truth predicate."""
        return _bool_truthiness(self.z3_bool, truthy=True)

    def is_falsy(self) -> z3.BoolRef:
        """Return the negation of the represented Boolean."""
        return _bool_truthiness(self.z3_bool, truthy=False)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return modeled equality with Boolean or integer values."""
        if isinstance(other, SymbolicBool):
            return self.z3_bool == other.z3_bool
        from .int import SymbolicInt

        if isinstance(other, SymbolicInt):
            return z3.If(self.z3_bool, other.z3_int == 1, other.z3_int == 0)
        return Z3_FALSE

    def __and__(self, other: SymbolicBool) -> SymbolicBool:
        """Return conjunction of two Boolean carrier expressions."""
        return SymbolicBool(z3.And(self.z3_bool, other.z3_bool))

    def __or__(self, other: SymbolicBool) -> SymbolicBool:
        """Return disjunction of two Boolean carrier expressions."""
        return SymbolicBool(z3.Or(self.z3_bool, other.z3_bool))

    def __invert__(self) -> SymbolicBool:
        """Return Boolean negation of this carrier expression."""
        return SymbolicBool(z3.Not(self.z3_bool))

    def __xor__(self, other: SymbolicBool) -> SymbolicBool:
        """Return exclusive disjunction of two Boolean carrier expressions."""
        return SymbolicBool(z3.Xor(self.z3_bool, other.z3_bool))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBool:
        """Create an unconstrained symbolic Boolean expression."""
        name = name or fresh_name("bool")
        return SymbolicBool(z3.Bool(name), name)

    @staticmethod
    def concrete(value: bool) -> SymbolicBool:
        """Create a Boolean value from a concrete Python ``bool``."""
        return SymbolicBool(Z3_TRUE if value else Z3_FALSE, str(value))
