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

"""Shift operators for scalar symbolic values."""

from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.scalars.value.protocols import (
    SymbolicValueSelf,
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

SymbolicValue = unbound_symbolic_value_constructor()


def bind_shift_symbolic_value_class(value_cls: ValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by shifts."""
    global SymbolicValue
    SymbolicValue = value_cls


class ValueShiftMixin:
    """Encode integral shifts through signed 64-bit bit-vector conversions."""

    def __lshift__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return the 64-bit encoded left-shift result channel.

        Limitations:
            A definite concrete negative shift raises. Symbolic negative shift
            counts are not split into an exception path here, and the bounded
            bit-vector encoding is not arbitrary-width Python integer shift.
        """
        concrete = ScalarValueOps.apply_concrete_integral_binary_op(
            self,
            other,
            lambda a, b: a << b,
        )
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)
        other_num = ScalarValueOps.extract_concrete_numeric(other)
        if isinstance(other_num, int) and other_num < 0:
            msg = "negative shift count"
            raise ValueError(msg)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = ScalarValueOps.int_to_bv(self.z3_int)
            right_bv = ScalarValueOps.int_to_bv(other.z3_int)
            res_bv = left_bv << right_bv
            return SymbolicValue(
                _name=f"({self.name}<<{other.name})",
                z3_int=ScalarValueOps.bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        left_bv = ScalarValueOps.int_to_bv(self.z3_int)
        right_bv = ScalarValueOps.int_to_bv(other.z3_int)
        res_bv = left_bv << right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self.name}<<{other.name})",
            z3_int=ScalarValueOps.bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="int",
        )

    def __rlshift__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Delegate reflected left shift through the same bounded encoding."""
        other = SymbolicValue.from_const(other)
        return other.__lshift__(self)

    def __rshift__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return the signed 64-bit arithmetic-right-shift result channel.

        Limitations:
            A definite concrete negative shift raises. Symbolic negative shift
            counts are not split into an exception path here, and the bounded
            representation is not arbitrary-width Python integer shift.
        """
        concrete = ScalarValueOps.apply_concrete_integral_binary_op(
            self,
            other,
            lambda a, b: a >> b,
        )
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)
        other_num = ScalarValueOps.extract_concrete_numeric(other)
        if isinstance(other_num, int) and other_num < 0:
            msg = "negative shift count"
            raise ValueError(msg)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = ScalarValueOps.int_to_bv(self.z3_int)
            right_bv = ScalarValueOps.int_to_bv(other.z3_int)
            res_bv = left_bv >> right_bv
            return SymbolicValue(
                _name=f"({self.name}>>{other.name})",
                z3_int=ScalarValueOps.bv_to_int(res_bv),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        left_bv = ScalarValueOps.int_to_bv(self.z3_int)
        right_bv = ScalarValueOps.int_to_bv(other.z3_int)
        res_bv = left_bv >> right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self.name}>>{other.name})",
            z3_int=ScalarValueOps.bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="int",
        )

    def __rrshift__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Delegate reflected right shift through the same bounded encoding."""
        other = SymbolicValue.from_const(other)
        return other.__rshift__(self)
