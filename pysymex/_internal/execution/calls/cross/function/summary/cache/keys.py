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

"""Canonical key construction for cross-function summary cache entries."""

from __future__ import annotations

from functools import lru_cache

import z3

from pysymex._internal.core.solver.constraints.hashing import structural_hash_sorted
from pysymex._internal.core.solver.independence.optimizer import IndependenceOptimizer
from pysymex._internal.core.types.scalars.values import SymbolicValue


@lru_cache(maxsize=512)
def canonical_int_arg_symbol(index: int) -> z3.ArithRef:
    """Return a stable canonical integer placeholder for argument index."""
    return z3.Int(f"arg_{index}_int")


@lru_cache(maxsize=512)
def canonical_bool_arg_symbol(index: int) -> z3.BoolRef:
    """Return a stable canonical boolean placeholder for argument index."""
    return z3.Bool(f"arg_{index}_bool")


def symbolic_value_arg_key(arg: SymbolicValue) -> str:
    """Return the argument-shape key for a symbolic value."""
    arg_type = type(arg).__name__
    constant_value = getattr(arg, "_constant_value", None)
    if constant_value is not None:
        value_type = type(constant_value).__name__
        return f"{arg_type}:{arg.type_tag}:const:{value_type}:{constant_value!r}"
    if z3.is_true(arg.is_none):
        return f"{arg_type}:NoneType:const:NoneType:None"
    return f"{arg_type}:{arg.type_tag}"


def compute_summary_key(
    func_name: str,
    args: list[object],
    path_constraints: list[z3.BoolRef],
) -> tuple[str, tuple[str, ...], int]:
    """Compute canonical hash key for arguments and their constraints."""
    canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    target_vars: set[z3.ExprRef] = set()
    sym_args: list[str] = []
    for index, arg in enumerate(args):
        arg_type = type(arg).__name__
        if isinstance(arg, SymbolicValue):
            target_vars.add(arg.z3_int)
            canonical_map.append((arg.z3_int, canonical_int_arg_symbol(index)))
            target_vars.add(arg.z3_bool)
            canonical_map.append((arg.z3_bool, canonical_bool_arg_symbol(index)))
            sym_args.append(symbolic_value_arg_key(arg))
        else:
            sym_args.append(f"{arg_type}:{arg!s}")
    if (not path_constraints) or (not target_vars):
        constraint_hash_value = 0
    else:
        constraint_hash_value = constraint_hash(path_constraints, target_vars, canonical_map)
    return (func_name, tuple(sym_args), constraint_hash_value)


def constraint_hash(
    path_constraints: list[z3.BoolRef],
    target_vars: set[z3.ExprRef],
    canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]],
) -> int:
    """Compute structural hash for constraints relevant to target variables."""
    optimizer = IndependenceOptimizer()
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
