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

"""Boolean-style bitwise operators for scalar symbolic values."""

from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.value.protocols import (
    SymbolicValueSelf,
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

SymbolicValue = unbound_symbolic_value_constructor()


def _nonnegative_integral_mask(value: object) -> int | None:
    mask = ScalarValueOps.extract_concrete_integral(value)
    if mask is None or mask < 0:
        return None
    return mask


def _bounded_mask_result(value: SymbolicValueSelf, left: object, right: object) -> SymbolicValueSelf:
    mask = _nonnegative_integral_mask(left)
    if mask is None:
        mask = _nonnegative_integral_mask(right)
    if mask is not None:
        value.min_val = 0
        value.max_val = mask
    return value


def bind_bitwise_logic_symbolic_value_class(value_cls: ValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by bitwise logic."""
    global SymbolicValue
    SymbolicValue = value_cls


class ValueBitwiseLogicMixin:
    """Encode Boolean logic or signed 64-bit integral bitwise operations."""

    def __and__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return Boolean conjunction or bounded integer bitwise conjunction."""
        concrete = ScalarValueOps.apply_concrete_integral_binary_op(self, other, lambda a, b: a & b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = ScalarValueOps.int_to_bv(self.z3_int)
            right_bv = ScalarValueOps.int_to_bv(other.z3_int)
            res_bv = left_bv & right_bv
            return _bounded_mask_result(
                SymbolicValue(
                    _name=f"({self.name}&{other.name})",
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
                ),
                self,
                other,
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self.name}&{other.name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.And(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = ScalarValueOps.int_to_bv(self.z3_int)
        right_bv = ScalarValueOps.int_to_bv(other.z3_int)
        res_bv = left_bv & right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return _bounded_mask_result(
            SymbolicValue(
                _name=f"({self.name}&{other.name})",
                z3_int=ScalarValueOps.bv_to_int(res_bv),
                is_int=is_int_res,
                z3_bool=z3.And(self.z3_bool, other.z3_bool),
                is_bool=z3.And(self.is_bool, other.is_bool),
            ),
            self,
            other,
        )

    def __rand__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Reflected bitwise AND operator."""
        return self.__and__(other)

    def __or__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return Boolean disjunction or bounded integer bitwise disjunction."""
        concrete = ScalarValueOps.apply_concrete_integral_binary_op(self, other, lambda a, b: a | b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            left_bv = ScalarValueOps.int_to_bv(self.z3_int)
            right_bv = ScalarValueOps.int_to_bv(other.z3_int)
            res_bv = left_bv | right_bv
            return SymbolicValue(
                _name=f"({self.name}|{other.name})",
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

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self.name}|{other.name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=z3.Or(self.z3_bool, other.z3_bool),
                is_bool=Z3_TRUE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="bool",
            )

        left_bv = ScalarValueOps.int_to_bv(self.z3_int)
        right_bv = ScalarValueOps.int_to_bv(other.z3_int)
        res_bv = left_bv | right_bv
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        return SymbolicValue(
            _name=f"({self.name}|{other.name})",
            z3_int=ScalarValueOps.bv_to_int(res_bv),
            is_int=is_int_res,
            z3_bool=z3.Or(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
        )

    def __ror__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Reflected bitwise OR operator."""
        return self.__or__(other)
