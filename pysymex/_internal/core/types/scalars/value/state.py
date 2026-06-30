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

"""State and merge behavior for scalar symbolic values."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.affinity import (
    ALWAYS_FALSY_AFFINITIES,
    ALWAYS_TRUTHY_AFFINITIES,
    LENGTH_CHANNEL_AFFINITIES,
    AffinityKind,
)
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.value.protocols import (
    SymbolicValueSelf,
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue

_symbolic_value_cls = unbound_symbolic_value_constructor()


def _known_bool_truthiness(expr: z3.BoolRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for concrete Boolean expressions."""
    if z3.is_true(expr):
        return Z3_TRUE if truthy else Z3_FALSE
    if z3.is_false(expr):
        return Z3_FALSE if truthy else Z3_TRUE
    if truthy:
        return expr
    return z3.Not(expr)


def _known_int_truthiness(expr: z3.ArithRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for concrete integer expressions."""
    if z3.eq(expr, Z3_ZERO):
        return Z3_FALSE if truthy else Z3_TRUE
    if z3.is_int_value(expr):
        return Z3_TRUE if truthy else Z3_FALSE
    if truthy:
        return expr != 0
    return expr == 0


def _known_string_truthiness(expr: z3.SeqRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for concrete string expressions."""
    if z3.is_string_value(expr):
        is_nonempty = expr.as_string() != ""
        if truthy:
            return Z3_TRUE if is_nonempty else Z3_FALSE
        return Z3_FALSE if is_nonempty else Z3_TRUE
    if truthy:
        return z3.Length(expr) > 0
    return z3.Length(expr) == 0


def _known_fp_truthiness(expr: z3.FPRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for concrete FP expressions."""
    if z3.is_fp_value(expr):
        is_nonzero = not expr.isZero()
        if truthy:
            return Z3_TRUE if is_nonzero else Z3_FALSE
        return Z3_FALSE if is_nonzero else Z3_TRUE
    if truthy:
        return z3.Not(z3.fpIsZero(expr))
    return z3.fpIsZero(expr)


def bind_state_symbolic_value_class(value_cls: ValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by merge operations."""
    global _symbolic_value_cls
    _symbolic_value_cls = value_cls


class ValueStateMixin:
    """Build truthiness predicates and branch-selected unified values.

    Limitations:
        Path- and object-affinity values are always truthy in this encoding;
        list and dictionary truthiness use the stored integer channel as a
        length-like value.
    """

    def could_be_truthy(self: SymbolicValueSelf) -> z3.BoolRef:
        """Return the cached or derived truthiness predicate for this carrier."""
        cached = self._truthy_cache
        if cached is not None:
            return cached

        self_affinity = self.affinity_type

        if self_affinity == AffinityKind.BOOL:
            result = _known_bool_truthiness(self.z3_bool, truthy=True)
        elif self_affinity == AffinityKind.INT:
            result = _known_int_truthiness(self.z3_int, truthy=True)
        elif self_affinity == AffinityKind.FLOAT:
            result = _known_fp_truthiness(self.z3_float, truthy=True)
        elif self_affinity == AffinityKind.STR:
            result = _known_string_truthiness(self.z3_str, truthy=True)
        elif self_affinity == AffinityKind.BYTES:
            result = _known_int_truthiness(z3.Length(self.z3_bytes), truthy=True)
        elif self_affinity in LENGTH_CHANNEL_AFFINITIES:
            result = _known_int_truthiness(self.z3_int, truthy=True)
        elif self_affinity in ALWAYS_TRUTHY_AFFINITIES:
            result = Z3_TRUE
        elif self_affinity in ALWAYS_FALSY_AFFINITIES:
            result = Z3_FALSE
        else:
            result = z3.Or(
                z3.And(self.is_bool, self.z3_bool),
                z3.And(self.is_int, self.z3_int != 0),
                z3.And(self.is_str, z3.Length(self.z3_str) > 0),
                z3.And(self.is_bytes, z3.Length(self.z3_bytes) > 0),
                z3.And(self.is_float, z3.Not(z3.fpIsZero(self.z3_float))),
                z3.And(self.is_list, self.z3_int != 0),
                z3.And(self.is_dict, self.z3_int != 0),
                z3.And(self.is_tuple, self.z3_int != 0),
                z3.And(self.is_set, self.z3_int != 0),
                self.is_path,
                self.is_obj,
            )

        self._truthy_cache = result
        return result

    def could_be_falsy(self: SymbolicValueSelf) -> z3.BoolRef:
        """Return the cached or derived falsiness predicate for this carrier."""
        cached = self._falsy_cache
        if cached is not None:
            return cached

        self_affinity = self.affinity_type

        if self_affinity == AffinityKind.BOOL:
            result = _known_bool_truthiness(self.z3_bool, truthy=False)
        elif self_affinity == AffinityKind.INT:
            result = _known_int_truthiness(self.z3_int, truthy=False)
        elif self_affinity == AffinityKind.FLOAT:
            result = _known_fp_truthiness(self.z3_float, truthy=False)
        elif self_affinity == AffinityKind.STR:
            result = _known_string_truthiness(self.z3_str, truthy=False)
        elif self_affinity == AffinityKind.BYTES:
            result = _known_int_truthiness(z3.Length(self.z3_bytes), truthy=False)
        elif self_affinity in LENGTH_CHANNEL_AFFINITIES:
            result = _known_int_truthiness(self.z3_int, truthy=False)
        elif self_affinity in ALWAYS_FALSY_AFFINITIES:
            result = Z3_TRUE
        elif self_affinity in ALWAYS_TRUTHY_AFFINITIES:
            result = Z3_FALSE
        else:
            result = z3.Or(
                z3.And(self.is_bool, z3.Not(self.z3_bool)),
                z3.And(self.is_int, self.z3_int == 0),
                z3.And(self.is_float, z3.fpIsZero(self.z3_float)),
                z3.And(self.is_str, z3.Length(self.z3_str) == 0),
                z3.And(self.is_bytes, z3.Length(self.z3_bytes) == 0),
                z3.And(self.is_list, self.z3_int == 0),
                z3.And(self.is_dict, self.z3_int == 0),
                z3.And(self.is_tuple, self.z3_int == 0),
                z3.And(self.is_set, self.z3_int == 0),
                self.is_none,
            )

        self._falsy_cache = result
        return result

    def conditional_merge(
        self: SymbolicValueSelf,
        other: object,
        condition: z3.BoolRef,
    ) -> SymbolicValueSelf:
        """Return a carrier whose represented channels are selected by ``condition``.

        Limitations:
            The returned carrier merges Z3 channels and selected activity
            metadata; attached modeled objects, constant bounds, annotations,
            and cached truthiness are not preserved here.
        """
        if isinstance(other, SymbolicNoneType):
            merged = other.conditional_merge(self, z3.Not(condition))
            from pysymex._internal.core.types.scalars.values import SymbolicValue as _SV

            if isinstance(merged, _SV):
                return merged
            return _symbolic_value_cls.from_const(merged)

        from pysymex._internal.core.types.scalars.values import SymbolicValue as _SV

        if not isinstance(other, _SV):
            other_sv: SymbolicValue = _symbolic_value_cls.from_const(other)
        else:
            other_sv = other

        if self is other_sv:
            return self

        def merge_arith(self_val: z3.ArithRef, other_val: z3.ArithRef) -> z3.ArithRef:
            """Return one arithmetic expression selected by ``condition``."""
            if self_val is other_val:
                return self_val
            if Z3ExpressionOps.safe_eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_bool(self_val: z3.BoolRef, other_val: z3.BoolRef) -> z3.BoolRef:
            """Return one Boolean expression selected by ``condition``."""
            if self_val is other_val:
                return self_val
            if Z3ExpressionOps.safe_eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_str(self_val: z3.SeqRef, other_val: z3.SeqRef) -> z3.SeqRef:
            """Return one string expression selected by ``condition``."""
            if self_val is other_val:
                return self_val
            if Z3ExpressionOps.safe_eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        def merge_float(self_val: z3.FPRef, other_val: z3.FPRef) -> z3.FPRef:
            """Return one FP expression selected by ``condition``."""
            if self_val is other_val:
                return self_val
            if Z3ExpressionOps.safe_eq(self_val, other_val):
                return self_val
            return z3.If(condition, self_val, other_val)

        merged_array: z3.ArrayRef | None = None
        if self.z3_array is not None and other_sv.z3_array is not None:
            if self.z3_array is other_sv.z3_array or Z3ExpressionOps.safe_eq(
                self.z3_array,
                other_sv.z3_array,
            ):
                merged_array = self.z3_array
            else:
                array_expr = cast("z3.ArrayRef", z3.If(condition, self.z3_array, other_sv.z3_array))
                merged_array = array_expr
        elif self.z3_array is not None:
            merged_array = self.z3_array
        elif other_sv.z3_array is not None:
            merged_array = other_sv.z3_array

        return _symbolic_value_cls(
            _name=f"If({condition}, {self.name}, {other_sv.name})",
            _h_active=getattr(self, "_h_active", False) or getattr(other_sv, "_h_active", False),
            z3_int=merge_arith(self.z3_int, other_sv.z3_int),
            is_int=merge_bool(self.is_int, other_sv.is_int),
            z3_bool=merge_bool(self.z3_bool, other_sv.z3_bool),
            is_bool=merge_bool(self.is_bool, other_sv.is_bool),
            z3_str=merge_str(self.z3_str, other_sv.z3_str),
            is_str=merge_bool(self.is_str, other_sv.is_str),
            z3_bytes=merge_str(self.z3_bytes, other_sv.z3_bytes),
            is_bytes=merge_bool(self.is_bytes, other_sv.is_bytes),
            z3_addr=merge_arith(self.z3_addr, other_sv.z3_addr),
            is_obj=merge_bool(self.is_obj, other_sv.is_obj),
            is_path=merge_bool(self.is_path, other_sv.is_path),
            is_none=merge_bool(self.is_none, other_sv.is_none),
            z3_float=merge_float(self.z3_float, other_sv.z3_float),
            is_float=merge_bool(self.is_float, other_sv.is_float),
            is_list=merge_bool(self.is_list, other_sv.is_list),
            is_dict=merge_bool(self.is_dict, other_sv.is_dict),
            is_tuple=merge_bool(self.is_tuple, other_sv.is_tuple),
            is_set=merge_bool(self.is_set, other_sv.is_set),
            z3_array=merged_array,
            affinity_type=(
                self.affinity_type
                if self.affinity_type == other_sv.affinity_type
                else AffinityKind.UNKNOWN
            ),
        )
