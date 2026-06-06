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

"""Structural hashing and cached literal helpers for Z3 constraints."""

from __future__ import annotations

import weakref
import math
from collections import OrderedDict
from typing import Final

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.logger import get_logger

_INT_CACHE: dict[int, z3.IntNumRef] = {}
_REAL_CACHE: OrderedDict[str, z3.ArithRef] = OrderedDict()
_BITVEC_CACHE: OrderedDict[tuple[int, int], z3.BitVecNumRef] = OrderedDict()
_FLOAT64_CACHE: dict[str, z3.FPNumRef] = {}
_STRING_CACHE: OrderedDict[str, z3.SeqRef] = OrderedDict()
_FLOAT64_SORT: Final = z3.Float64()
_Z3_HASH_ATTR: Final = "_symex_hash"
_SEQUENCE_CACHE_MIN_LENGTH: Final = 64
_SEQUENCE_CACHE_MAX_ENTRIES: Final = 4096
_STRING_CACHE_MAX_ENTRIES: Final = 4096
_STRING_CACHE_MAX_LENGTH: Final = 256
_REAL_CACHE_MAX_ENTRIES: Final = 4096
_REAL_CACHE_MAX_LENGTH: Final = 64
_BITVEC_CACHE_MAX_ENTRIES: Final = 4096
logger = get_logger(__name__)


def get_int_val(val: int) -> z3.IntNumRef:
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


def get_bool_val(val: bool) -> z3.BoolRef:
    """Return the shared Z3 boolean literal for a Python truth value."""
    return Z3_TRUE if val else Z3_FALSE


def get_real_val(val: int | float | str) -> z3.ArithRef:
    """Return a cached Z3 real constant for bounded common literals."""
    if is_process_cache_disabled():
        return z3.RealVal(val)
    if isinstance(val, float) and not math.isfinite(val):
        return z3.RealVal(val)
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


def get_bitvec_val(val: int, width: int) -> z3.BitVecNumRef:
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


def get_float64_val(val: float) -> z3.FPNumRef:
    """Return a cached Z3 Float64 constant for finite common literals."""
    if is_process_cache_disabled():
        return z3.FPVal(val, _FLOAT64_SORT)
    if not math.isfinite(val) or not -256.0 <= val <= 2048.0:
        return z3.FPVal(val, _FLOAT64_SORT)
    key = val.hex()
    cached = _FLOAT64_CACHE.get(key)
    if cached is not None:
        return cached
    z3_val = z3.FPVal(val, _FLOAT64_SORT)
    _FLOAT64_CACHE[key] = z3_val
    return z3_val


def get_string_val(val: str) -> z3.SeqRef:
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


def _attached_hash(constraint: z3.ExprRef) -> int | None:
    """Return the expression-local cached hash when present."""
    cached = getattr(constraint, _Z3_HASH_ATTR, None)
    return cached if isinstance(cached, int) else None


def _try_attach_hash(constraint: z3.ExprRef, computed: int) -> bool:
    """Attach *computed* to a Z3 wrapper and report whether it succeeded."""
    try:
        setattr(constraint, _Z3_HASH_ATTR, computed)
    except AttributeError:
        return False
    return True


def _compute_attached_hash(constraint: z3.ExprRef) -> int:
    """Compute and attach a Z3 structural hash for the common fast path."""
    computed = constraint.hash()
    _try_attach_hash(constraint, computed)
    return computed


def _combined_attached_hash(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Return an ordered tuple hash using expression-local hash caches."""
    if not constraints:
        return 0

    hashes: list[int] = []
    append_hash = hashes.append
    hash_attr = _Z3_HASH_ATTR
    for constraint in constraints:
        cached: int | None = getattr(constraint, hash_attr, None)
        if cached is not None:
            append_hash(cached)
        else:
            append_hash(_compute_attached_hash(constraint))
    return hash(tuple(hashes))


class ConstraintHasher:
    """Stateful Z3 structural-hash helper with a fallback weakref cache.

    Normal Z3 Python wrappers allow dynamic attributes, so the hot path stores
    each structural hash directly on the wrapper. The per-instance weakref cache
    is retained only for wrappers that cannot carry attributes, avoiding stale
    id reuse while keeping the common path allocation-light.

    Limitations:
        Hashes are prefilters only; callers making correctness decisions must
        validate candidate expressions after a matching hash.
    """

    def __init__(self, max_cache_size: int = 1_000_000) -> None:
        """Initialize a new constraint hasher with empty cache.

        Args:
            max_cache_size: Maximum number of cached expression ids before
                the cache is cleared to avoid long-lived stale-id reuse.
        """
        if max_cache_size <= 0:
            raise ValueError("max_cache_size must be > 0")
        self.cache: dict[int, tuple[weakref.ReferenceType[z3.ExprRef], int]] = {}
        self._sequence_cache: dict[int, tuple[tuple[weakref.ReferenceType[z3.ExprRef], ...], int]]
        self._sequence_cache = {}
        self._max_cache_size = max_cache_size
        self._max_sequence_cache_size = min(max_cache_size, _SEQUENCE_CACHE_MAX_ENTRIES)

    def clear(self) -> None:
        """Clear the internal fallback caches.

        Expression-local attached hashes remain on their Z3 wrappers; this
        mirrors the previous behavior where ``clear`` did not remove attached
        ``_symex_hash`` attributes.
        """
        self.cache.clear()
        self._sequence_cache.clear()

    def cache_size(self) -> int:
        """Return the number of entries in the fallback weakref cache."""
        self._prune_dead_entries()
        return len(self.cache)

    def _prune_dead_entries(self) -> None:
        """Remove entries whose Z3 wrapper has been garbage-collected."""
        stale_ids: list[int] = [
            expr_id for expr_id, (expr_ref, _) in self.cache.items() if expr_ref() is None
        ]
        for expr_id in stale_ids:
            del self.cache[expr_id]

    def hash_expr(self, constraint: z3.ExprRef) -> int:
        """Return a cached Z3 structural hash for one expression."""
        if is_process_cache_disabled():
            return constraint.hash()

        attached = _attached_hash(constraint)
        if attached is not None:
            return attached

        constraint_id = id(constraint)
        cached = self.cache.get(constraint_id)
        if cached is not None:
            cached_expr, cached_hash = cached
            if cached_expr() is constraint:
                return cached_hash

        computed = constraint.hash()
        if _try_attach_hash(constraint, computed):
            return computed

        if len(self.cache) >= self._max_cache_size:
            self._prune_dead_entries()
        if len(self.cache) >= self._max_cache_size:
            logger.verbose("Clearing constraint hash fallback cache at size=%d", len(self.cache))
            self.cache.clear()
        self.cache[constraint_id] = (weakref.ref(constraint), computed)
        return computed

    def structural_hash(self, constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
        """Compute an ordered combined hash of Z3 expression structures.

        The hot path reads expression-local cached hashes directly and falls
        back to :meth:`hash_expr` only for uncached expressions. Repeated long
        lists also use a guarded sequence cache that validates every live
        expression object before returning a cached combined hash.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            Integer hash suitable as a prefilter component of a cache key.

        Limitations:
            Hash equality does not prove equality of constraint sequences.
        """
        if not constraints:
            return 0

        if is_process_cache_disabled():
            return hash(tuple(constraint.hash() for constraint in constraints))

        constraint_count = len(constraints)
        if constraint_count >= _SEQUENCE_CACHE_MIN_LENGTH:
            sequence_cache_key = id(constraints)
            sequence_cached = self._sequence_cache.get(sequence_cache_key)
            if sequence_cached is not None:
                cached_refs, cached_hash = sequence_cached
                if len(cached_refs) == constraint_count:
                    for cached_ref, constraint in zip(cached_refs, constraints, strict=True):
                        if cached_ref() is not constraint:
                            break
                    else:
                        return cached_hash

        hashes: list[int] = []
        append_hash = hashes.append
        hash_attr = _Z3_HASH_ATTR
        hash_uncached = self.hash_expr
        for c in constraints:
            cached: int | None = getattr(c, hash_attr, None)
            if cached is not None:
                append_hash(cached)
            else:
                append_hash(hash_uncached(c))

        combined = hash(tuple(hashes))
        if constraint_count >= _SEQUENCE_CACHE_MIN_LENGTH:
            if len(self._sequence_cache) >= self._max_sequence_cache_size:
                self._sequence_cache.clear()
            self._sequence_cache[id(constraints)] = (
                tuple(weakref.ref(constraint) for constraint in constraints),
                combined,
            )
        return combined


def structural_hash(
    constraints: list[z3.BoolRef] | list[z3.ExprRef],
    hasher: ConstraintHasher | None = None,
) -> int:
    """Compute an ordered combined hash of Z3 expression structures.

    Args:
        constraints: List of Z3 boolean constraints.
        hasher: Optional :class:`ConstraintHasher` used to reuse live-wrapper
            hash computations.

    Returns:
        Integer hash suitable as a prefilter component of a cache key.

    Limitations:
        Hash equality does not prove equality of constraint sequences.
    """
    if is_process_cache_disabled():
        return hash(tuple(constraint.hash() for constraint in constraints))
    if hasher is None:
        return _combined_attached_hash(constraints)
    return hasher.structural_hash(constraints)


def structural_hash_sorted(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute an order-independent structural hash of Z3 constraints.

    Sorts constraint hashes before combining so that the same set of
    constraints in any order produces the same hash.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash independent of constraint ordering.

    Limitations:
        Hash equality does not prove equality of unordered constraint sets.
    """
    if not constraints:
        return 0
    if is_process_cache_disabled():
        return hash(tuple(sorted(constraint.hash() for constraint in constraints)))
    hashes: list[int] = []
    append_hash = hashes.append
    hash_attr = _Z3_HASH_ATTR
    for constraint in constraints:
        cached: int | None = getattr(constraint, hash_attr, None)
        if cached is not None:
            append_hash(cached)
        else:
            append_hash(_compute_attached_hash(constraint))
    hashes.sort()
    return hash(tuple(hashes))


def clear_constraint_value_caches() -> None:
    """Clear process-local Z3 literal and structural hash helper caches."""
    _INT_CACHE.clear()
    _REAL_CACHE.clear()
    _BITVEC_CACHE.clear()
    _FLOAT64_CACHE.clear()
    _STRING_CACHE.clear()


register_process_cache_clearer(
    "core.constraint_value_caches",
    clear_constraint_value_caches,
)
