"""Tests for Constraint Independence Integration in IncrementalSolver."""

import pytest

import z3

from pysymex.core.solver import IncrementalSolver


class TestSolverIndependence:
    def test_independent_clusters_sat(self):
        """Verify SAT correctness with independent constraints."""

        solver = IncrementalSolver()

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [x > 0, y < 0, x < 10, y > -10]

        assert solver.is_sat(constraints) is True

    def test_independent_clusters_unsat_x(self):
        """Verify UNSAT handling when one independent cluster is UNSAT."""

        solver = IncrementalSolver()

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [x > 0, x < 0, y == 5]

        assert solver.is_sat(constraints) is False

    def test_independent_clusters_unsat_y(self):
        """Verify UNSAT handling when another independent cluster is UNSAT."""

        solver = IncrementalSolver()

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [x == 5, y > 0, y < 0]

        assert solver.is_sat(constraints) is False

    def test_dependent_cluster(self):
        """Verify correctness for dependent constraints (entangled)."""

        solver = IncrementalSolver()

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [x > 0, y > 0, x + y < 0]

        assert solver.is_sat(constraints) is False

    def test_cache_reuse_optimization(self):
        """Verify that solving [A, B] reuses cached results for [A] and [B] if independent."""

        solver = IncrementalSolver()

        x = z3.Int("x")

        y = z3.Int("y")

        c_x = [x > 0, x < 10]

        c_y = [y > 100, y < 200]

        assert solver.is_sat(c_x) is True

        hits_initial = solver._cache_hits

        assert solver.is_sat(c_y) is True

        assert solver.is_sat(c_x + c_y) is True

        assert solver._cache_hits > hits_initial + 1, "Should have hits for sub-clusters"

    def test_trivial_constraints(self):
        """Verify behavior with empty or constant constraints."""

        solver = IncrementalSolver()

        assert solver.is_sat([]) is True

        assert solver.is_sat([z3.BoolVal(True)]) is True

        assert solver.is_sat([z3.BoolVal(False)]) is False

        x = z3.Int("x")

        assert solver.is_sat([x > 0, z3.BoolVal(True)]) is True

        assert solver.is_sat([x > 0, z3.BoolVal(False)]) is False
