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

"""Cached Z3 inputs for built-in benchmark workloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

LoopUnrollingWorkload = tuple[list["z3.BoolRef"], list["z3.BoolRef"]]
LinearConstraintsWorkload = list["z3.BoolRef"]
IncrementalSolverWorkload = list[list["z3.BoolRef"]]

_loop_unrolling_workload_cache: LoopUnrollingWorkload | None = None
_linear_constraints_workload_cache: LinearConstraintsWorkload | None = None
_incremental_solver_workload_cache: IncrementalSolverWorkload | None = None


def loop_unrolling_workload() -> LoopUnrollingWorkload:
    """Return prebuilt linear constraints for the loop-unrolling solver benchmark."""
    global _loop_unrolling_workload_cache
    if _loop_unrolling_workload_cache is None:
        import z3

        x = z3.Int("x")
        base_constraints = [x >= 0, x < 1000]
        suffix_constraints = [x > i * 10 for i in range(50)]
        _loop_unrolling_workload_cache = (base_constraints, suffix_constraints)
    return _loop_unrolling_workload_cache


def linear_constraints_workload() -> LinearConstraintsWorkload:
    """Return prebuilt linear constraints for the bulk-solver benchmark."""
    global _linear_constraints_workload_cache
    if _linear_constraints_workload_cache is None:
        import z3

        vars_ = [z3.Int(f"v{i}") for i in range(100)]
        constraints = [vars_[i] + 1 <= vars_[i + 1] for i in range(99)]
        constraints.append(vars_[0] >= 0)
        constraints.append(vars_[99] <= 1000)
        _linear_constraints_workload_cache = constraints
    return _linear_constraints_workload_cache


def incremental_solver_workload() -> IncrementalSolverWorkload:
    """Return prebuilt per-scope constraints for the incremental solver benchmark."""
    global _incremental_solver_workload_cache
    if _incremental_solver_workload_cache is None:
        import z3

        x, y = z3.Ints("x y")
        _incremental_solver_workload_cache = [
            [x > i, y > i, x + y < i * 3 + 10] for i in range(100)
        ]
    return _incremental_solver_workload_cache
