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

"""Validated weakref cache for constraint-independence slices."""

from __future__ import annotations

import weakref
from collections import OrderedDict

import z3

from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)

SliceCacheEntry = tuple[
    tuple[weakref.ReferenceType[z3.BoolRef], ...],
    weakref.ReferenceType[z3.BoolRef],
    tuple[int, ...],
]
SliceCache = OrderedDict[int, list[SliceCacheEntry]]


def slice_cache_key(
    path_constraints: list[z3.BoolRef],
    query: z3.BoolRef,
    query_vars: frozenset[str],
) -> int:
    """Build a cheap prefilter key from path, query, and variable hashes.

    Cache keys are not proof evidence. Lookup validates live path and query
    expressions before reuse, so this key can stay cheap.
    """
    path_hashes = tuple(c.hash() for c in path_constraints)

    return hash(
        (
            len(path_constraints),
            path_hashes,
            query.hash(),
            tuple(sorted(query_vars)),
        ),
    )


def lookup_slice_cache(
    cache: SliceCache,
    cache_key: int,
    path_constraints: list[z3.BoolRef],
    query: z3.BoolRef,
) -> list[z3.BoolRef] | None:
    """Return a cached slice only after validating live path and query ASTs."""
    bucket = cache.get(cache_key)
    if bucket is None:
        return None

    cache.move_to_end(cache_key)
    stale_entries: list[SliceCacheEntry] = []
    for entry in list(bucket):
        cached_path_refs, cached_query_ref, cached_indices = entry
        cached_query = cached_query_ref()
        if cached_query is None:
            stale_entries.append(entry)
            continue
        cached_path: list[z3.BoolRef] = []
        stale_path = False
        for cached_ref in cached_path_refs:
            cached_constraint = cached_ref()
            if cached_constraint is None:
                stale_path = True
                break
            cached_path.append(cached_constraint)
        if stale_path:
            stale_entries.append(entry)
            continue
        if len(cached_path) != len(path_constraints):
            continue
        try:
            if cached_query is not query and not Z3ExpressionOps.safe_eq(cached_query, query):
                continue
            if not all(
                cached is current or Z3ExpressionOps.safe_eq(cached, current)
                for cached, current in zip(cached_path, path_constraints, strict=True)
            ):
                continue
        except z3.Z3Exception:
            if logger.state.debug_enabled:
                logger.debug("Slice cache validation failed", exc_info=True)
            continue
        if logger.state.trace_enabled:
            logger.trace("Constraint slice cache hit key=%d", cache_key)
        if len(cached_indices) == len(path_constraints):
            return path_constraints
        return [path_constraints[index] for index in cached_indices]

    for stale_entry in stale_entries:
        bucket.remove(stale_entry)
    if not bucket:
        del cache[cache_key]

    return None


def store_slice_cache(
    cache: SliceCache,
    cache_key: int,
    path_constraints: list[z3.BoolRef],
    query: z3.BoolRef,
    relevant_indices: tuple[int, ...],
    *,
    max_size: int,
) -> None:
    """Store weak references and retained indices in the bounded slice cache."""
    entry: SliceCacheEntry = (
        tuple(weakref.ref(constraint) for constraint in path_constraints),
        weakref.ref(query),
        relevant_indices,
    )
    bucket = cache.get(cache_key)
    if bucket is None:
        cache[cache_key] = [entry]
    else:
        bucket.append(entry)
        cache.move_to_end(cache_key)
    while len(cache) > max_size:
        cache.popitem(last=False)
