"""Tests for Constraint Independence Integration in IncrementalSolver."""

import z3

from pysymex.core.solver import IncrementalSolver


class TestSolverIndependence:
    def test_independent_clusters_sat(self):
        """Verify SAT correctness with independent constraints."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")
        # Independent constraints
        constraints = [x > 0, y < 0, x < 10, y > -10]
        # Should be split into {x...} and {y...}
        assert solver.is_sat(constraints) is True

    def test_independent_clusters_unsat_x(self):
        """Verify UNSAT handling when one independent cluster is UNSAT."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")
        # x is UNSAT, y is SAT
        constraints = [x > 0, x < 0, y == 5]
        assert solver.is_sat(constraints) is False

    def test_independent_clusters_unsat_y(self):
        """Verify UNSAT handling when another independent cluster is UNSAT."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")
        # x is SAT, y is UNSAT
        constraints = [x == 5, y > 0, y < 0]
        assert solver.is_sat(constraints) is False

    def test_dependent_cluster(self):
        """Verify correctness for dependent constraints (entangled)."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")
        # Linked by x+y
        constraints = [x > 0, y > 0, x + y < 0]  # UNSAT
        assert solver.is_sat(constraints) is False

    def test_cache_reuse_optimization(self):
        """Verify that solving [A, B] reuses cached results for [A] and [B] if independent."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        c_x = [x > 0, x < 10]
        c_y = [y > 100, y < 200]

        # 1. check and cache X
        assert solver.is_sat(c_x) is True
        hits_initial = solver._cache_hits

        # 2. check and cache Y
        assert solver.is_sat(c_y) is True

        # 3. check combined [X, Y]
        # This is a NEW query (structurally distinct from X or Y).
        # But it splits into cluster X and cluster Y.
        # Both cluster X and cluster Y match the previous queries structurally.
        # So we expect cache hits for the clusters.
        assert solver.is_sat(c_x + c_y) is True

        # We expect hits for X and Y lookup inside is_sat loop
        # The global lookup for [X, Y] is a miss (first time).
        # Then clustering happens.
        # Then looking up cluster X -> hit?
        # Then looking up cluster Y -> hit?

        # Note: structural_hash must be stable locally.
        # It is (Merkle tree / content hash).

        # Therefore, hits should increase significantly
        assert solver._cache_hits > hits_initial + 1, "Should have hits for sub-clusters"

    def test_trivial_constraints(self):
        """Verify behavior with empty or constant constraints."""
        solver = IncrementalSolver()
        assert solver.is_sat([]) is True

        # Independent constants
        assert solver.is_sat([z3.BoolVal(True)]) is True
        assert solver.is_sat([z3.BoolVal(False)]) is False

        # Mixed vars and constants
        x = z3.Int("x")
        assert solver.is_sat([x > 0, z3.BoolVal(True)]) is True
        assert solver.is_sat([x > 0, z3.BoolVal(False)]) is False
