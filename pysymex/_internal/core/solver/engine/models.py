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

"""Model extraction, implication, and solver statistics for IncrementalSolver."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.types import SolverMixinContract


class SolverModelMixin(SolverMixinContract):
    """Extract models, counterexamples, implications, cores, and statistics.

    Methods route satisfiability through the engine's structured query
    operations; model and implication helpers do not turn solver uncertainty
    into positive proof results.
    """

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Return a model only for encoded constraints established SAT.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            A Z3 model for SAT, or ``None`` for UNSAT or UNKNOWN.

        """
        result = self.check_sat_cached(constraints)
        return result.model if result.is_sat else None

    def get_model_string(self, constraints: list[z3.BoolRef]) -> str | None:
        """Return string form of an established SAT model, if available."""
        model = self.get_model(constraints)
        if model is not None:
            return str(model)
        return None

    def simplify(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Return Z3's simplified expression without making a solver-outcome claim."""
        return simplify_expr(expr)

    def get_stats(self) -> dict[str, object]:
        """Return accumulated query, cache, translation, scope, and timing counters.

        ``logical_queries`` counts low-level ``check()`` attempts, including
        exact low-level cache hits. ``z3_check_calls`` and its compatibility
        alias ``queries`` count physical calls to ``z3.Solver.check``.
        """
        return {
            "queries": self._z3_check_count,
            "logical_queries": self._query_count,
            "z3_check_calls": self._z3_check_count,
            "sat_results": self._sat_result_count,
            "unsat_results": self._unsat_result_count,
            "unknown_results": self._unknown_result_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self.cache),
            "check_cache_size": len(self._check_cache),
            "unsat_subset_cache_size": len(self._unsat_subset_cache),
            "z3_ast_cache_hits": self._z3_ast_cache_hits,
            "z3_ast_cache_misses": self._z3_ast_cache_misses,
            "z3_ast_cache_hit_rate": round(
                self._z3_ast_cache_hits
                / max(1, self._z3_ast_cache_hits + self._z3_ast_cache_misses),
                4,
            ),
            "z3_ast_cache_size": len(self._z3_ast_cache),
            "scope_depth": self._scope_depth,
            "solver_time_ms": round(self._solver_time_ms, 2),
            "warm_start_models": len(self._last_models),
        }

    def __repr__(self) -> str:
        """Return a diagnostic summary of query, cache, and scope counters."""
        return (
            f"IncrementalSolver(z3_check_calls={self._z3_check_count}, "
            f"logical_queries={self._query_count}, "
            f"cache_hits={self._cache_hits}, scope={self._scope_depth})"
        )


def z3_value_to_python(z3_val: z3.ExprRef) -> object:
    """Convert common concrete Z3 model literals into displayable Python values."""
    if z3.is_int_value(z3_val):
        return z3_val.as_long()
    if z3.is_bool(z3_val):
        return z3.is_true(z3_val)
    if z3.is_string_value(z3_val):
        return z3_val.as_string()
    if z3.is_rational_value(z3_val):
        return float(z3_val.as_fraction())
    if isinstance(z3_val, z3.RatNumRef):
        denominator = z3_val.denominator_as_long()
        if denominator != 0:
            return z3_val.numerator_as_long() / denominator
    if z3.is_real(z3_val):
        decimal = z3_val.as_decimal(10).rstrip("?")
        if "/" in decimal:
            numerator, denominator = decimal.split("/", 1)
            return int(numerator) / int(denominator)
        return float(decimal)
    return str(z3_val)
