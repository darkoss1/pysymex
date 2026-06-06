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

"""Cross-function summary cache."""

from __future__ import annotations

from collections import OrderedDict
from functools import lru_cache
from typing import Final

import z3

from pysymex.core.solver.constraints.hashing import structural_hash_sorted
from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer
from pysymex.core.types.scalars.values import SymbolicValue

FUNCTION_SUMMARY_CACHE_MAX_ENTRIES: Final[int] = 2048


@lru_cache(maxsize=512)
def canonical_int_arg_symbol(index: int) -> z3.ArithRef:
    """Return a stable canonical integer placeholder for argument index."""
    return z3.Int(f"arg_{index}_int")


@lru_cache(maxsize=512)
def canonical_bool_arg_symbol(index: int) -> z3.BoolRef:
    """Return a stable canonical boolean placeholder for argument index."""
    return z3.Bool(f"arg_{index}_bool")


class FunctionSummaryCache:
    """Cache for function summaries supporting canonicalized constraint hashing."""

    def __init__(self, max_size: int = FUNCTION_SUMMARY_CACHE_MAX_ENTRIES) -> None:
        """Initialize a new FunctionSummaryCache instance with empty cache and stats."""
        if max_size < 0:
            raise ValueError("Function summary cache max_size must be non-negative")
        self.max_size = max_size
        self.cache: OrderedDict[tuple[str, tuple[str, ...], int], object] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _symbolic_value_arg_key(arg: SymbolicValue) -> str:
        """Return the argument-shape key for a symbolic value."""
        arg_type = type(arg).__name__
        constant_value = getattr(arg, "_constant_value", None)
        if constant_value is not None:
            value_type = type(constant_value).__name__
            return f"{arg_type}:{arg.type_tag}:const:{value_type}:{constant_value!r}"
        if z3.is_true(arg.is_none):
            return f"{arg_type}:NoneType:const:NoneType:None"
        return f"{arg_type}:{arg.type_tag}"

    def get(
        self, func_name: str, args: list[object], path_constraints: list[z3.BoolRef]
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
        self, func_name: str, args: list[object], path_constraints: list[z3.BoolRef]
    ) -> tuple[str, tuple[str, ...], int]:
        """Compute canonical hash key for arguments and their constraints."""
        canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
        target_vars: set[z3.ExprRef] = set()
        sym_args: list[str] = []
        for i, arg in enumerate(args):
            arg_type = type(arg).__name__
            if isinstance(arg, SymbolicValue):
                target_vars.add(arg.z3_int)
                canonical_map.append((arg.z3_int, canonical_int_arg_symbol(i)))
                target_vars.add(arg.z3_bool)
                canonical_map.append((arg.z3_bool, canonical_bool_arg_symbol(i)))
                sym_args.append(self._symbolic_value_arg_key(arg))
            else:
                sym_args.append(f"{arg_type}:{arg!s}")
        if (not path_constraints) or (not target_vars):
            constraint_hash = 0
        else:
            constraint_hash = self._constraint_hash(path_constraints, target_vars, canonical_map)
        return (func_name, tuple(sym_args), constraint_hash)

    @staticmethod
    def _constraint_hash(
        path_constraints: list[z3.BoolRef],
        target_vars: set[z3.ExprRef],
        canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]],
    ) -> int:
        """Compute structural hash for constraints relevant to target variables.

        This method extracts path constraints related to the specified target variables
        using a constraint independence optimizer, substitutes them with canonical variables,
        and computes a stable structural hash of the canonicalized constraints to enable
        effective caching.

        Args:
            path_constraints: A list of Z3 boolean expressions representing the path constraints.
            target_vars: A set of Z3 expression references representing the variables of interest.
            canonical_map: A list of tuples mapping original Z3 variables to their canonical
                representatives.

        Returns:
            An integer representing the structural hash of the sliced and canonicalized constraints.
        """
        optimizer = ConstraintIndependenceOptimizer()
        for constraint in path_constraints:
            optimizer.register_constraint(constraint)
        dummy_query = z3.And(*[(var == var) for var in target_vars])
        relevant_slice = optimizer.slice_for_query(path_constraints, dummy_query)
        canonical_constraints: list[z3.BoolRef] = []
        for constraint in relevant_slice:
            if canonical_map:
                canonical_constraints.append(z3.substitute(constraint, *canonical_map))
            else:
                canonical_constraints.append(constraint)
        return structural_hash_sorted(canonical_constraints)


__all__ = ["FunctionSummaryCache", "canonical_bool_arg_symbol", "canonical_int_arg_symbol"]
