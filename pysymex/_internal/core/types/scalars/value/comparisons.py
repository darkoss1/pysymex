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

"""Comparison and logical operators for scalar symbolic values."""

from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.value.protocols import (
    SymbolicValueSelf,
    ValueConstructor,
    unbound_symbolic_value_constructor,
)

SymbolicValue = unbound_symbolic_value_constructor()


def bind_comparison_symbolic_value_class(value_cls: ValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by comparisons."""
    global SymbolicValue
    SymbolicValue = value_cls


class ValueComparisonMixin:
    """Construct Boolean-valued logical and modeled comparison expressions.

    Limitations:
        Ordered comparisons encode integer and Float64 numeric cases only;
        this mixin does not independently generate Python ``TypeError`` paths
        for unsupported operand types.
    """

    def logical_not(self: SymbolicValueSelf) -> SymbolicValueSelf:
        """Return a Boolean carrier negating the modeled truthiness predicate."""
        return SymbolicValue(
            _name=f"(not {self.name})",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=z3.Not(self.could_be_truthy()),
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __eq__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return modeled equality across recognized scalar and object channels."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int == other.z3_int
            return SymbolicValue(
                _name=f"({self.name}=={other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            cond = self.z3_bool == other.z3_bool
            return SymbolicValue(
                _name=f"({self.name}=={other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int == other.z3_int),
            z3.And(self.is_bool, other.is_bool, self.z3_bool == other.z3_bool),
            z3.And(self.is_str, other.is_str, self.z3_str == other.z3_str),
            z3.And(self.is_bytes, other.is_bytes, self.z3_bytes == other.z3_bytes),
            z3.And(self.is_float, other.is_float, self.z3_float == other.z3_float),
            z3.And(self.is_none, other.is_none),
            z3.And(self.is_obj, other.is_obj, self.z3_addr == other.z3_addr),
            z3.And(self.is_int, other.is_float, other.z3_float == self_as_fp),
            z3.And(self.is_float, other.is_int, self.z3_float == other_as_fp),
            z3.And(
                self.is_bool,
                other.is_int,
                z3.If(self.z3_bool, Z3_ONE, Z3_ZERO) == other.z3_int,
            ),
            z3.And(
                self.is_int,
                other.is_bool,
                self.z3_int == z3.If(other.z3_bool, Z3_ONE, Z3_ZERO),
            ),
        )
        return SymbolicValue(
            _name=f"({self.name}=={other.name})",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __ne__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return the logical negation of modeled equality."""
        return self.__eq__(other).logical_not()

    def __lt__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return modeled less-than for integer and Float64 numeric channels."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int < other.z3_int
            return SymbolicValue(
                _name=f"({self.name}<{other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int < other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLT(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpLT(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpLT(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self.name}<{other.name})",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __le__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return modeled less-than-or-equal for integer and Float64 channels."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int <= other.z3_int
            return SymbolicValue(
                _name=f"({self.name}<={other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int <= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpLEQ(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpLEQ(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpLEQ(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self.name}<={other.name})",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __gt__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return modeled greater-than for integer and Float64 numeric channels."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int > other.z3_int
            return SymbolicValue(
                _name=f"({self.name}>{other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int > other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGT(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpGT(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpGT(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self.name}>{other.name})",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )

    def __ge__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return modeled greater-than-or-equal for integer and Float64 channels."""
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            cond = self.z3_int >= other.z3_int
            return SymbolicValue(
                _name=f"({self.name}>={other.name})",
                z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=cond,
                is_bool=Z3_TRUE,
                affinity_type="bool",
            )

        self_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
        other_as_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
        cond = z3.Or(
            z3.And(self.is_int, other.is_int, self.z3_int >= other.z3_int),
            z3.And(self.is_float, other.is_float, z3.fpGEQ(self.z3_float, other.z3_float)),
            z3.And(self.is_int, other.is_float, z3.fpGEQ(self_as_fp, other.z3_float)),
            z3.And(self.is_float, other.is_int, z3.fpGEQ(self.z3_float, other_as_fp)),
        )
        return SymbolicValue(
            _name=f"({self.name}>={other.name})",
            z3_int=z3.If(cond, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=cond,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
