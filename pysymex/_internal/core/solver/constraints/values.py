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

"""Cached Z3 literal builders for solver constraints.

This module owns process-local wrapper caches for small and repeated concrete
Z3 literals. The helpers preserve Z3 expression semantics; callers must not use
wrapper identity as proof of formula equality.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from typing import Final

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE

_INT_CACHE: dict[int, z3.IntNumRef] = {}
_REAL_CACHE: OrderedDict[str, z3.ArithRef] = OrderedDict()
_BITVEC_CACHE: OrderedDict[tuple[int, int], z3.BitVecNumRef] = OrderedDict()
_FLOAT64_CACHE: dict[tuple[float, float], z3.FPNumRef] = {}
_STRING_CACHE: OrderedDict[str, z3.SeqRef] = OrderedDict()
_INT_STR_CACHE: dict[int, str] = {i: str(i) for i in range(-256, 2049)}
_FLOAT64_SORT: Final = z3.Float64()
_STRING_CACHE_MAX_ENTRIES: Final = 4096
_STRING_CACHE_MAX_LENGTH: Final = 256
_REAL_CACHE_MAX_ENTRIES: Final = 4096
_REAL_CACHE_MAX_LENGTH: Final = 64
_BITVEC_CACHE_MAX_ENTRIES: Final = 4096


class ConstraintValues:
    """Cached Z3 literal builders for solver constraints.

    This class owns process-local wrapper caches for small and repeated concrete
    Z3 literals. The helpers preserve Z3 expression semantics; callers must not use
    wrapper identity as proof of formula equality.
    """

    @staticmethod
    def int(val: int) -> z3.IntNumRef:
        """Return a cached Z3 integer constant."""
        if is_process_cache_disabled():
            return z3.IntVal(val)
        cached = _INT_CACHE.get(val)
        if cached is not None:
            return cached
        z3_val = z3.IntVal(val)
        if -256 <= val <= 2048:
            _INT_CACHE[val] = z3_val
        return z3_val

    @staticmethod
    def bool(val: bool) -> z3.BoolRef:
        """Return the shared Z3 boolean literal for a Python truth value."""
        return Z3_TRUE if val else Z3_FALSE

    @staticmethod
    def real(val: int | float | str) -> z3.ArithRef:
        """Return a cached Z3 real constant for bounded common literals."""
        if is_process_cache_disabled():
            return z3.RealVal(val)
        if isinstance(val, float) and not math.isfinite(val):
            return z3.RealVal(val)
        if isinstance(val, str):
            key = val
        elif isinstance(val, int):
            key = _INT_STR_CACHE.get(val)
            if key is None:
                key = str(val)
        else:
            key = str(val)

        if len(key) > _REAL_CACHE_MAX_LENGTH:
            return z3.RealVal(val)
        cached = _REAL_CACHE.get(key)
        if cached is not None:
            _REAL_CACHE.move_to_end(key)
            return cached
        z3_val = z3.RealVal(val)
        _REAL_CACHE[key] = z3_val
        if len(_REAL_CACHE) > _REAL_CACHE_MAX_ENTRIES:
            _REAL_CACHE.popitem(last=False)
        return z3_val

    @staticmethod
    def bitvec(val: int, width: int) -> z3.BitVecNumRef:
        """Return a cached Z3 bit-vector constant for bounded common literals."""
        if is_process_cache_disabled():
            return z3.BitVecVal(val, width)
        key = (val, width)
        cached = _BITVEC_CACHE.get(key)
        if cached is not None:
            _BITVEC_CACHE.move_to_end(key)
            return cached
        z3_val = z3.BitVecVal(val, width)
        _BITVEC_CACHE[key] = z3_val
        if len(_BITVEC_CACHE) > _BITVEC_CACHE_MAX_ENTRIES:
            _BITVEC_CACHE.popitem(last=False)
        return z3_val

    @staticmethod
    def float64(val: float) -> z3.FPNumRef:
        """Return a cached Z3 Float64 constant for finite common literals."""
        if is_process_cache_disabled():
            return z3.FPVal(val, _FLOAT64_SORT)
        if not math.isfinite(val) or not -256.0 <= val <= 2048.0:
            return z3.FPVal(val, _FLOAT64_SORT)
        key = (val, math.copysign(1.0, val))
        cached = _FLOAT64_CACHE.get(key)
        if cached is not None:
            return cached
        z3_val = z3.FPVal(val, _FLOAT64_SORT)
        _FLOAT64_CACHE[key] = z3_val
        return z3_val

    @staticmethod
    def string(val: str) -> z3.SeqRef:
        """Return a cached Z3 string literal for bounded common strings."""
        if is_process_cache_disabled():
            return z3.StringVal(val)
        if len(val) > _STRING_CACHE_MAX_LENGTH:
            return z3.StringVal(val)
        cached = _STRING_CACHE.get(val)
        if cached is not None:
            _STRING_CACHE.move_to_end(val)
            return cached
        z3_val = z3.StringVal(val)
        _STRING_CACHE[val] = z3_val
        if len(_STRING_CACHE) > _STRING_CACHE_MAX_ENTRIES:
            _STRING_CACHE.popitem(last=False)
        return z3_val

    @staticmethod
    def clear_caches() -> None:
        """Clear process-local Z3 literal wrapper caches."""
        _INT_CACHE.clear()
        _REAL_CACHE.clear()
        _BITVEC_CACHE.clear()
        _FLOAT64_CACHE.clear()
        _STRING_CACHE.clear()


register_process_cache_clearer(
    "core.constraint_value_caches",
    ConstraintValues.clear_caches,
)
