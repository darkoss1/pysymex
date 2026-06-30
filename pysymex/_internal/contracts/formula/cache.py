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

"""Thread-safe LRU cache for compiled string contract predicates.

Used by :class:`~pysymex._internal.contracts.compiler.ContractCompiler` to reuse ``z3.BoolRef``
values keyed by predicate text and symbol AST identifiers. Callable predicates are
not cached because closure state may differ between compilations. Does not run
solver queries or inject VM checks.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.control import register_process_cache_clearer

if TYPE_CHECKING:
    import z3

CompileCacheKey = tuple[int, tuple[int, ...]]


class FormulaCache:
    """Thread-safe LRU cache for compiled Z3 formulas.

    Prevents redundant recompilation of identical string contract predicate
    structures (such as invariants or postconditions) across exploration paths
    or verification checks.

    Key lookup is based on a tuple containing AST metadata hashes and symbol
    hashes.
    """

    __slots__ = ("_max_size", "cache", "lock")

    def __init__(self, max_size: int = 4096) -> None:
        """Create a cache with the given LRU capacity.

        Args:
            max_size: Maximum retained entries (at least 1).

        Raises:
            ValueError: If ``max_size`` is less than 1.

        """
        if max_size < 1:
            msg = "max_size must be at least 1"
            raise ValueError(msg)
        self.cache: OrderedDict[CompileCacheKey, z3.BoolRef] = OrderedDict()
        self.lock = threading.Lock()
        self._max_size = max_size

    def get(self, key: CompileCacheKey) -> z3.BoolRef | None:
        """Retrieve a cached formula for the given cache key.

        Args:
            key: The compiled cache key containing the predicate AST hash and
                symbol identifiers.

        Returns:
            The cached ``z3.BoolRef`` if found, or ``None`` on cache miss.

        Side Effects:
            Updates the cache order to mark the accessed entry as most recently used.

        """
        with self.lock:
            formula = self.cache.get(key)
            if formula is not None:
                self.cache.move_to_end(key)
            return formula

    def put(self, key: CompileCacheKey, formula: z3.BoolRef) -> None:
        """Store a compiled Z3 formula in the cache.

        Args:
            key: The unique compile cache key identifier.
            formula: The Z3 boolean expression to cache.

        Side Effects:
            Appends the formula to the cache. Evicts the least recently used
            formulas if the cache exceeds its maximum configured size.

        """
        with self.lock:
            self.cache[key] = formula
            self.cache.move_to_end(key)
            while len(self.cache) > self._max_size:
                self.cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all entries from the cache.

        Side Effects:
            Empties the underlying OrderedDict cache.
        """
        with self.lock:
            self.cache.clear()


formula_cache = FormulaCache()
register_process_cache_clearer("contracts.formula.cache", formula_cache.clear)
