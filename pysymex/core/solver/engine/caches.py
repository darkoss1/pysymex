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

"""Shared cache records and small structural caches for solver APIs."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol

import z3

from pysymex.core.solver.engine.results import SolverResult

CACHE_CONTEXT_MASK = (1 << 128) - 1
UNSAT_SUBSET_CACHE_MAX_ENTRIES = 128
CONSTRAINT_FINGERPRINT_CACHE_MAX_ENTRIES = 4096


@dataclass(frozen=True, slots=True)
class CheckCacheEntry:
    """Cached low-level check result with exact context collision validation."""

    context: tuple[z3.BoolRef, ...]
    assumptions: tuple[z3.BoolRef, ...]
    result: SolverResult


@dataclass(frozen=True, slots=True)
class AstTranslationCacheEntry:
    """Cached BoolRef translated into this solver's Z3 context."""

    source: z3.BoolRef
    translated: z3.BoolRef


@dataclass(frozen=True, slots=True)
class UnsatSubsetCacheEntry:
    """Cached UNSAT conjunction usable as evidence for later supersets."""

    constraints: tuple[z3.BoolRef, ...]
    constraint_hashes: tuple[int, ...]
    constraint_hash_counts: tuple[tuple[int, int], ...]


class StructuralCache:
    """Small LRU store keyed by caller-supplied structural hash values.

    Notes:
        This container performs no collision validation itself; callers must
        use it only where their key/value contract is sufficient.
    """

    _MISSING = object()

    def __init__(self, maxsize: int = 512) -> None:
        """Create an empty cache with an LRU entry limit."""
        self._data: OrderedDict[int, object] = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: int) -> tuple[bool, object | None]:
        """Retrieve a cached value for a given structural hash.

        Returns:
            A ``(cache_hit, value)`` pair. A hit refreshes the entry's LRU
            position.
        """
        value = self._data.get(key, self._MISSING)
        if value is self._MISSING:
            return False, None
        self._data.move_to_end(key)
        return True, value

    def put(self, key: int, value: object) -> None:
        """Insert a value and evict the least recently used entry if needed."""
        self._data[key] = value
        self._data.move_to_end(key)
        if len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def clear(self) -> None:
        """Empty the cache to reclaim memory."""
        self._data.clear()


class ClearableCache(Protocol):
    """Protocol for registered caches that can release retained entries."""

    def clear(self) -> None:
        """Remove all entries retained by this cache."""
        ...


class TranslatableZ3Expr(Protocol):
    """Z3 expression surface for context translation."""

    def translate(self, target: z3.Context) -> z3.ExprRef:
        """Return this expression translated into ``target``."""
        ...
