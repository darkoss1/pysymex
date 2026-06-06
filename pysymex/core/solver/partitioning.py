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

"""Constraint partitioning with serialized solver checks.

This module owns the solver-side partitioned-check adapter. It may split input
constraints into independent groups for cheaper checks, but every Z3 operation
is serialized and every inconclusive partition remains an explicit
``SolverResult.unknown()``.
"""

from __future__ import annotations

import z3

from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer
from pysymex.logger import get_logger

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)


class ConstraintPartitioner:
    """Group constraints by shared registered free-variable names.

    The independence optimizer connects constraints that share variables.
    Constant constraints are collected in a separate ``"CONST"`` partition.

    Limitations:
        This object produces candidate independent partitions; it does not
        itself run a solver or establish a parallel-execution guarantee.
    """

    def partition(self, constraints: list[z3.BoolRef]) -> list[list[z3.BoolRef]]:
        """Return constraint partitions induced by registered variables."""
        if not constraints:
            return []

        optimizer = ConstraintIndependenceOptimizer()
        constraint_vars: list[frozenset[str]] = []
        for c in constraints:
            constraint_vars.append(optimizer.register_constraint(c))

        partitions: dict[str, list[z3.BoolRef]] = {}
        for c, var_names in zip(constraints, constraint_vars, strict=False):
            if not var_names:
                root = "CONST"
            else:
                root = optimizer.find_group_root(next(iter(var_names)))
            if root not in partitions:
                partitions[root] = []
            partitions[root].append(c)
        return list(partitions.values())


class ParallelSolver:
    """Partitioned solver adapter using serialized incremental Z3 checks.

    Splits a constraint set via :class:`ConstraintPartitioner`, solves each
    partition through :class:`IncrementalSolver`, and combines definite
    per-partition models. Z3 checks are intentionally serialized because
    solving shared Python/Z3 ASTs from multiple Python threads can crash the
    native solver runtime.

    Args:
        timeout_ms: Per-partition solver timeout in milliseconds.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        """Initialize serialized partition checking."""
        self.timeout_ms = timeout_ms
        self._partitioner = ConstraintPartitioner()

    def check(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Check partitions serially and combine definite partition models.

        Returns:
            ``SolverResult.unsat()`` if a partition is proved unsatisfiable.
            ``SolverResult.sat(model)`` if partition checks and model
            combination produce a satisfiable result. ``SolverResult.unknown()``
            represents inconclusive partition checks or model combination.

        Limitations:
            Partition independence is an optimization boundary, not a proof of
            full-program independence.
        """
        if not constraints:
            return SolverResult.sat(None)
        partitions = self._partitioner.partition(constraints)
        logger.verbose(
            "Partitioned solver checking %d constraint(s) in %d partition(s)",
            len(constraints),
            len(partitions),
        )
        models: list[z3.ModelRef] = []
        errors: list[Exception] = []
        for partition in partitions:
            try:
                result = self._solve_partition(partition)
            except (z3.Z3Exception, RuntimeError, TimeoutError) as exc:
                logger.warning("Partitioned solver partition failed", exc_info=True)
                errors.append(exc)
                continue
            if result.is_unsat:
                return SolverResult.unsat()
            if result.is_unknown:
                return SolverResult.unknown()
            if result.model is not None:
                models.append(result.model)
            else:
                return SolverResult.unknown()
        if errors:
            return SolverResult.unknown()
        return self._combine_models(models)

    def _solve_partition(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Return the typed solver result for one serialized partition check."""
        solver = IncrementalSolver(timeout_ms=self.timeout_ms)
        try:
            solver.add(*constraints)
            result = solver.check(need_model=True)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Partitioned solver failed while asserting a partition", exc_info=True)
            return SolverResult.unknown()
        if result.is_sat:
            return result if result.model is not None else SolverResult.unknown()
        if result.is_unsat:
            return SolverResult.unsat()
        return SolverResult.unknown()

    def _combine_models(self, models: list[z3.ModelRef]) -> SolverResult:
        """Attempt to combine per-partition assignments into one model."""
        if not models:
            return SolverResult.unknown()
        if len(models) == 1:
            return SolverResult.sat(models[0])

        combined = IncrementalSolver(timeout_ms=self.timeout_ms)
        model_constraints: list[z3.BoolRef] = []
        for model in models:
            for decl in model.decls():
                model_constraints.append(decl() == model[decl])
        try:
            combined.add(*model_constraints)
            combined_result = combined.check(need_model=True)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Partitioned solver failed while combining models", exc_info=True)
            return SolverResult.unknown()
        if combined_result.is_sat:
            return combined_result if combined_result.model is not None else SolverResult.unknown()
        if combined_result.is_unsat:
            logger.debug("Partitioned solver selected models were mutually inconsistent")
            return SolverResult.unknown()
        return SolverResult.unknown()


__all__ = ["ConstraintPartitioner", "ParallelSolver"]
