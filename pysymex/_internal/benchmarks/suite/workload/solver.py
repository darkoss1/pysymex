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

"""Solver-focused built-in benchmark workloads."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.benchmarks.suite.workload.inputs import (
    incremental_solver_workload,
    linear_constraints_workload,
    loop_unrolling_workload,
)
from pysymex._internal.benchmarks.suite.workload.stats_ops import WorkloadStatsOps
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


def bench_simple_arithmetic() -> dict[str, int]:
    """Benchmark: IncrementalSolver arithmetic constraint solving."""
    import z3

    solver = IncrementalSolver(timeout_ms=5000)
    x, y, z = z3.Ints("x y z")
    constraints = [
        x + y == 11,
        x > 0,
        y > 0,
        x * y > 15,
        z == x - y,
        z < 5,
        z > -5,
        x + z > 2,
        y - z < 15,
        x * 2 + y * 3 == 27,
        x % 2 == 0,
        y % 2 != 0,
        z + 10 > x,
        x + y + z < 30,
        x > y,
        y > z,
        x * x > 10,
        y * y > 10,
        z * z < 100,
        x + y + z >= 5,
    ]
    result = solver.check_sat_result(constraints)
    if not result.is_sat:
        msg = "simple arithmetic benchmark expected a satisfiable workload"
        raise AssertionError(msg)

    stats = solver.get_stats()
    return {
        "instructions": len(constraints),
        "paths": 1,
        "solver_calls": WorkloadStatsOps.solver_queries_from_stats(stats),
        **WorkloadStatsOps.solver_outcome_counts_from_stats(stats),
    }


def bench_sat_cache_hits() -> dict[str, int]:
    """Benchmark: definitive SAT result cache hits for repeated equivalent queries."""
    import z3

    attempts = 128
    solver = IncrementalSolver(timeout_ms=5000)
    x, y = z3.Ints("cache_sat_x cache_sat_y")
    constraints = [
        x + y == 42,
        x > 5,
        y > 5,
        x < 40,
        y < 40,
        x > y,
    ]
    for _ in range(attempts):
        result = solver.check_sat_cached(constraints)
        if not result.is_sat:
            msg = "SAT cache benchmark expected a satisfiable workload"
            raise AssertionError(msg)

    stats = solver.get_stats()
    return {
        "instructions": attempts,
        "paths": 1,
        "solver_calls": WorkloadStatsOps.solver_queries_from_stats(stats),
        "cache_hits": _int_stat(stats, "cache_hits"),
        **WorkloadStatsOps.solver_outcome_counts_from_stats(stats),
    }


def bench_unsat_subset_cache_hits() -> dict[str, int]:
    """Benchmark: UNSAT subset reuse across supersets of a known contradiction."""
    import z3

    supersets = 128
    solver = IncrementalSolver(timeout_ms=5000)
    x, y = z3.Ints("cache_unsat_x cache_unsat_y")
    total = x + y
    contradiction = [total > 0, total < 0]
    if not solver.check_sat_result(contradiction).is_unsat:
        msg = "UNSAT subset benchmark expected the seed query to be unsatisfiable"
        raise AssertionError(msg)

    for index in range(supersets):
        result = solver.check_sat_result([*contradiction, x == index % 3])
        if not result.is_unsat:
            msg = "UNSAT subset cache benchmark expected all supersets to be unsat"
            raise AssertionError(msg)

    stats = solver.get_stats()
    return {
        "instructions": supersets + 1,
        "paths": 1,
        "solver_calls": WorkloadStatsOps.solver_queries_from_stats(stats),
        "cache_hits": _int_stat(stats, "cache_hits"),
        **WorkloadStatsOps.solver_outcome_counts_from_stats(stats),
    }


def bench_exact_literal_cache_hits() -> dict[str, int]:
    """Benchmark: exact Boolean literal classification across Z3 wrapper objects."""
    import z3

    from pysymex._internal.core.solver.constraints.exact.literal.cache import (
        clear_exact_bool_literal_cache,
    )
    from pysymex._internal.core.solver.constraints.literals import exact_bool_literal

    attempts = 2048
    expr = z3.IntVal(3) < z3.IntVal(4)
    clear_exact_bool_literal_cache()
    if exact_bool_literal(expr) is not True:
        msg = "exact literal benchmark expected a locally true comparison"
        raise AssertionError(msg)

    as_ast = cast("Callable[[], object]", getattr(expr, "as_ast"))  # noqa: B009
    bool_ref = cast("Callable[[object, object], object]", z3.BoolRef)
    for _ in range(attempts):
        equivalent_wrapper = cast("z3.BoolRef", bool_ref(as_ast(), expr.ctx))
        if exact_bool_literal(equivalent_wrapper) is not True:
            msg = "exact literal cache benchmark expected wrapper-equivalent cache hits"
            raise AssertionError(msg)

    return {"instructions": attempts + 1, "paths": 1, "solver_calls": 0}


def bench_branching() -> dict[str, int]:
    """Benchmark: 20-way branch explosion with IncrementalSolver."""
    import z3

    vars_ = [z3.Int(f"b{i}") for i in range(20)]
    solver = IncrementalSolver(timeout_ms=5000)
    paths = 0
    solver_calls = 0
    constraint_adds = 0
    for v in vars_:
        solver.push()
        solver.add(v > 0)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()
        solver.push()
        solver.add(v <= 0)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()

    return {"instructions": constraint_adds, "paths": paths, "solver_calls": solver_calls}


def bench_loop_unrolling() -> dict[str, int]:
    """Benchmark: loop with accumulating constraints."""
    solver = IncrementalSolver(timeout_ms=5000)
    base_constraints, suffix_constraints = loop_unrolling_workload()
    solver.add(*base_constraints)
    paths = 0
    solver_calls = 0
    constraint_adds = len(base_constraints)
    for constraint in suffix_constraints:
        solver.push()
        solver.add(constraint)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()

    return {"instructions": constraint_adds, "paths": paths, "solver_calls": solver_calls}


def bench_linear_constraints() -> dict[str, int]:
    """Benchmark: 100 linear integer constraints."""
    solver = IncrementalSolver(timeout_ms=10000, use_cache=False)
    constraints = linear_constraints_workload()
    constraint_adds = len(constraints)
    solver.add(*constraints)
    solver.check()

    return {"instructions": constraint_adds, "paths": 1, "solver_calls": 1}


def bench_incremental_solver() -> dict[str, int]:
    """Benchmark: IncrementalSolver push/pop performance."""
    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    calls = 0

    constraint_evals = 0
    for constraints in incremental_solver_workload():
        solver.push()
        try:
            solver.add(*constraints)
            solver.check()
            constraint_evals += len(constraints)
            calls += 1
        finally:
            solver.pop()

    return {"instructions": constraint_evals, "paths": 100, "solver_calls": calls}


def bench_constraint_hashing() -> dict[str, int]:
    """Benchmark: structural constraint hashing vs string-based."""
    try:
        from pysymex._internal.core.solver.constraints.hashing import (
            ConstraintHasher,
            structural_hash,
        )
    except ImportError:
        logger.warning("Constraint hashing unavailable for benchmark workload", exc_info=True)
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    x, y, z_var = z3.Ints("x y z")
    constraints = [
        x + y > 10,
        y - z_var < 5,
        x * 2 == z_var,
        x >= 0,
        y >= 0,
        z_var >= 0,
        x + y + z_var < 100,
    ]

    hasher = ConstraintHasher()

    hashes = 0
    for _ in range(10000):
        hasher.clear()
        structural_hash(constraints, hasher)
        hashes += 1

    return {"instructions": hashes * len(constraints), "paths": 0, "solver_calls": 0}


def _int_stat(stats: dict[str, object], key: str) -> int:
    """Return an integer solver stat while rejecting bool values."""
    value = stats.get(key, 0)
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    return 0
