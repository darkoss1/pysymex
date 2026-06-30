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

"""LRU storage for cross-function summaries."""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING, Final

from pysymex._internal.execution.calls.cross.function.summary.cache.keys import (
    compute_summary_key,
    constraint_hash,
    symbolic_value_arg_key,
)

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.types.scalars.values import SymbolicValue

FUNCTION_SUMMARY_CACHE_MAX_ENTRIES: Final[int] = 2048


class FunctionSummaryCache:
    """Cache for function summaries supporting canonicalized constraint hashing."""

    def __init__(self, max_size: int = FUNCTION_SUMMARY_CACHE_MAX_ENTRIES) -> None:
        """Initialize a new FunctionSummaryCache instance with empty cache and stats."""
        if max_size < 0:
            msg = "Function summary cache max_size must be non-negative"
            raise ValueError(msg)
        self.max_size = max_size
        self.cache: OrderedDict[tuple[str, tuple[str, ...], int], object] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _symbolic_value_arg_key(arg: SymbolicValue) -> str:
        """Return the argument-shape key for a symbolic value."""
        return symbolic_value_arg_key(arg)

    def get(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
    ) -> object | None:
        """Get a summary for a function call with specific arguments and constraints."""
        key = self.compute_key(func_name, args, path_constraints)
        if key in self.cache:
            self.hits += 1
            self.cache.move_to_end(key)
            return self.cache[key]
        self.misses += 1
        return None

    def put(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
        summary: object,
    ) -> None:
        """Cache a summary for a function call."""
        if self.max_size == 0:
            return
        key = self.compute_key(func_name, args, path_constraints)
        self.cache[key] = summary
        self.cache.move_to_end(key)
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def compute_key(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
    ) -> tuple[str, tuple[str, ...], int]:
        """Compute canonical hash key for arguments and their constraints."""
        return compute_summary_key(func_name, args, path_constraints)

    @staticmethod
    def _constraint_hash(
        path_constraints: list[z3.BoolRef],
        target_vars: set[z3.ExprRef],
        canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]],
    ) -> int:
        """Compute structural hash for constraints relevant to target variables."""
        return constraint_hash(path_constraints, target_vars, canonical_map)
