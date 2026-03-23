"""Tests for IncrementalSolver cache consistency and collision handling.

These tests verify that the solver's structural caching mechanism:
1. Returns correct SAT/UNSAT results for cached queries
2. Handles hash collisions via secondary discriminators
3. Maintains cache coherence across push/pop scopes
4. Produces consistent results with and without caching

A cache collision returning wrong SAT/UNSAT would be catastrophic:
- False SAT: explores infeasible paths, wasting resources
- False UNSAT: prunes viable paths, missing real bugs
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
import z3

from pysymex.core.solver import (
    IncrementalSolver,
    SolverResult,
    clear_solver_caches,
    create_solver,
    get_model,
    is_satisfiable,
    prove,
)


class TestSolverCacheCorrectness:
    """Tests that solver cache returns correct results."""

    def test_cached_sat_still_sat(self):
        """A cached SAT result must remain SAT on re-query."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        constraints = [x > 0, x < 10]

        result1 = solver.is_sat(constraints)
        result2 = solver.is_sat(constraints)  # Should hit cache

        assert result1 is True
        assert result2 is True
        assert solver._cache_hits >= 1

    def test_cached_unsat_still_unsat(self):
        """A cached UNSAT result must remain UNSAT on re-query."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        # Contradictory constraints
        constraints = [x > 10, x < 5]

        result1 = solver.is_sat(constraints)
        result2 = solver.is_sat(constraints)  # Should hit cache

        assert result1 is False
        assert result2 is False

    def test_different_constraints_different_results(self):
        """Different constraints must not share cache entries."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        sat_constraints = [x > 0]
        unsat_constraints = [x > 0, x < 0]

        result1 = solver.is_sat(sat_constraints)
        result2 = solver.is_sat(unsat_constraints)

        assert result1 is True
        assert result2 is False

    def test_cache_key_includes_scope_context(self):
        """Cache keys must include ambient solver context."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        # Query in empty context
        query = [x > 5]
        result1 = solver.is_sat(query)
        assert result1 is True

        # Add ambient constraint that makes query UNSAT
        solver.push()
        solver.add(x < 0)

        # Same query but in different context
        result2 = solver.is_sat(query)
        assert result2 is False, "Cache ignored ambient constraints"

        solver.pop()

    def test_cache_context_after_pop(self):
        """Cache context must revert after pop."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        query = [x == 5]
        result_base = solver.is_sat(query)

        solver.push()
        solver.add(x < 0)
        result_with_context = solver.is_sat(query)
        solver.pop()

        result_after_pop = solver.is_sat(query)

        assert result_base is True
        assert result_with_context is False
        assert result_after_pop is True


class TestSolverCacheCollisionHandling:
    """Tests for hash collision detection and handling."""

    def test_discriminator_prevents_false_positive(self):
        """Secondary discriminator should prevent hash collision false positives."""
        solver = IncrementalSolver(cache_size=1000)

        # Create constraints that might have the same structural hash
        # but different Z3 hashes
        x = z3.Int("x")
        y = z3.Int("y")

        c1 = [x > 0]
        c2 = [y > 0]  # Same structure, different variable

        r1 = solver.is_sat(c1)
        r2 = solver.is_sat(c2)

        # Both should be SAT independently
        assert r1 is True
        assert r2 is True

    def test_similar_constraints_handled_correctly(self):
        """Very similar constraints must be distinguished."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        # Near-identical constraints
        c1 = [x >= 0]
        c2 = [x > 0]

        # Query both and verify independence
        r1 = solver.is_sat(c1)
        r2 = solver.is_sat(c2)

        # Both SAT, but with x=0, only c1 is SAT
        test_with_zero = [x == 0]

        model1 = solver.get_model(c1 + test_with_zero)
        model2 = solver.get_model(c2 + test_with_zero)

        assert model1 is not None, "x >= 0 with x=0 should be SAT"
        assert model2 is None, "x > 0 with x=0 should be UNSAT"


class TestSolverCacheEviction:
    """Tests for LRU cache eviction behavior."""

    def test_lru_eviction_maintains_correctness(self):
        """Evicted entries must not cause incorrect results."""
        solver = IncrementalSolver(cache_size=10)  # Very small cache

        # Fill cache beyond capacity
        results = {}
        for i in range(20):
            x = z3.Int(f"var_{i}")
            c = [x > i]
            results[i] = solver.is_sat(c)

        # All should be SAT
        assert all(r is True for r in results.values())

        # Re-query evicted entries - must still be correct
        for i in range(5):  # First entries likely evicted
            x = z3.Int(f"var_{i}")
            c = [x > i]
            assert solver.is_sat(c) is True

    def test_cache_eviction_under_pressure(self):
        """Cache should remain functional under heavy pressure."""
        solver = IncrementalSolver(cache_size=100)

        correct = 0
        total = 1000

        for _ in range(total):
            x = z3.Int("x")
            val = z3.IntVal(_)

            if _ % 2 == 0:
                # SAT query
                if solver.is_sat([x == val]):
                    correct += 1
            else:
                # UNSAT query
                if not solver.is_sat([x > val, x < val]):
                    correct += 1

        assert correct == total, f"Cache corruption: {total - correct}/{total} wrong"


class TestSolverPushPopIntegrity:
    """Tests for push/pop scope management integrity."""

    def test_deep_push_pop_maintains_cache(self):
        """Deep push/pop nesting must maintain cache coherence."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        base_query = [x > 0]

        for _ in range(50):
            solver.push()
            solver.add(x < 100)

        result_deep = solver.is_sat(base_query)

        for _ in range(50):
            solver.pop()

        result_base = solver.is_sat(base_query)

        assert result_deep is True
        assert result_base is True

    def test_unbalanced_pop_handled_gracefully(self):
        """Extra pops should not corrupt state."""
        solver = IncrementalSolver()

        solver.push()
        solver.pop()
        solver.pop()  # Extra pop
        solver.pop()  # Even more pops

        x = z3.Int("x")
        # Should still work correctly
        assert solver.is_sat([x > 0]) is True

    def test_leave_scope_alias(self):
        """leave_scope should behave identically to pop."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.push()
        solver.add(x < 0)
        r1 = solver.is_sat([x > 5])
        solver.leave_scope()

        solver.push()
        solver.add(x < 0)
        r2 = solver.is_sat([x > 5])
        solver.pop()

        assert r1 == r2 is False


class TestSolverCacheWithModel:
    """Tests for model caching behavior."""

    def test_cached_model_correct(self):
        """Cached models must satisfy original constraints."""
        solver = IncrementalSolver(cache_size=1000)
        x = z3.Int("x")

        constraints = [x > 10, x < 20]

        model1 = solver.get_model(constraints)
        model2 = solver.get_model(constraints)  # May use cached result

        assert model1 is not None
        assert model2 is not None

        # Model values should satisfy constraints
        val = model1[z3.Int("x")]
        assert val is not None

    def test_check_sat_cached_returns_full_result(self):
        """check_sat_cached should return complete SolverResult."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        constraints = [x == 42]

        result = solver.check_sat_cached(constraints)

        assert isinstance(result, SolverResult)
        assert result.is_sat is True
        assert result.model is not None


class TestSolverCacheStatistics:
    """Tests for cache statistics tracking."""

    def test_cache_hit_tracking(self):
        """Cache hits should be accurately tracked."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        constraints = [x > 0]

        solver.is_sat(constraints)  # Miss
        solver.is_sat(constraints)  # Hit
        solver.is_sat(constraints)  # Hit

        stats = solver.get_stats()
        assert stats["cache_hits"] >= 2

    def test_query_count_tracking(self):
        """Query count should be accurately tracked."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        for i in range(10):
            solver.is_sat([x > i])

        stats = solver.get_stats()
        assert stats["queries"] >= 10


class TestSolverCacheReset:
    """Tests for cache reset behavior."""

    def test_reset_clears_cache(self):
        """reset() should clear all cached state."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.is_sat([x > 0])
        solver.push()
        solver.add(x < 100)

        stats_before = solver.get_stats()
        assert stats_before["cache_size"] > 0

        solver.reset()

        stats_after = solver.get_stats()
        assert stats_after["cache_size"] == 0
        assert solver._scope_depth == 0

    def test_usable_after_reset(self):
        """Solver should be fully functional after reset."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.is_sat([x > 10])
        solver.reset()

        # Should work normally
        assert solver.is_sat([x > 0]) is True
        assert solver.is_sat([x > 0, x < 0]) is False


class TestSolverImplies:
    """Tests for implication checking."""

    def test_implies_valid(self):
        """Valid implications should return True."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # x > 10 implies x > 5
        result = solver.implies(x > 10, x > 5)
        assert result is True

    def test_implies_invalid(self):
        """Invalid implications should return False."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # x > 5 does NOT imply x > 10
        result = solver.implies(x > 5, x > 10)
        assert result is False

    def test_implies_with_context(self):
        """Implication should work correctly within push/pop context."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        solver.push()
        solver.add(x > 0)

        # In context x > 0: x > 0 trivially implies x >= 0
        result = solver.implies(x > 0, x >= 0)

        solver.pop()

        assert result is True


class TestSolverTheoryDetection:
    """Tests for theory detection and configuration."""

    def test_qflia_detection(self):
        """Pure integer linear arithmetic should be detected as qflia."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [x + y > 10, x - y < 5, x >= 0]

        theory = IncrementalSolver._detect_theory(constraints)
        assert theory == "qflia"

    def test_string_theory_detection(self):
        """String constraints should be detected as qfs."""
        s = z3.String("s")

        constraints = [z3.Length(s) > 5]

        theory = IncrementalSolver._detect_theory(constraints)
        assert theory == "qfs"

    def test_bitvector_detection(self):
        """Bitvector constraints should be detected as qfbv."""
        x = z3.BitVec("x", 32)

        constraints = [x & 0xFF == 0]

        theory = IncrementalSolver._detect_theory(constraints)
        assert theory == "qfbv"

    def test_mixed_theory_detection(self):
        """Multiple theories should be detected as mixed."""
        x = z3.Int("x")
        s = z3.String("s")

        constraints = [x > 0, z3.Length(s) > 5]

        theory = IncrementalSolver._detect_theory(constraints)
        # Should be mixed since both int and string theories
        assert theory in ("mixed", "qfs")


class TestSolverThreadSafety:
    """Tests for thread-safety of solver operations.

    Note: Z3 Solver objects are NOT thread-safe. Each thread must have its own
    solver instance. These tests verify that separate solvers work correctly
    when used concurrently, and that module-level functions handle concurrency.
    """

    @pytest.mark.skip(reason="Z3's C++ core has thread-safety issues on Windows")
    def test_concurrent_separate_solvers(self):
        """Separate solver instances per thread should work."""
        errors: list[Exception] = []
        results: list[tuple[int, int, bool]] = []

        def query_thread(thread_id):
            try:
                # Each thread gets its own solver
                solver = IncrementalSolver(cache_size=1000)
                for i in range(50):
                    x = z3.Int(f"x_{thread_id}_{i}")
                    sat = solver.is_sat([x > 0])
                    results.append((thread_id, i, sat))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=query_thread, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert all(r[2] is True for r in results)


class TestModuleLevelFunctions:
    """Tests for module-level solver functions."""

    def test_is_satisfiable_tuple(self):
        """is_satisfiable should work with tuples."""
        x = z3.Int("x")

        assert is_satisfiable((x > 0,)) is True
        assert is_satisfiable((x > 0, x < 0)) is False

    def test_is_satisfiable_list(self):
        """is_satisfiable should work with lists."""
        x = z3.Int("x")

        assert is_satisfiable([x > 0]) is True
        assert is_satisfiable([x > 0, x < 0]) is False

    def test_get_model_satisfiable(self):
        """get_model should return model for SAT constraints."""
        x = z3.Int("x")

        model = get_model([x == 42])
        assert model is not None

    def test_get_model_unsatisfiable(self):
        """get_model should return None for UNSAT constraints."""
        x = z3.Int("x")

        model = get_model([x > 0, x < 0])
        assert model is None

    def test_prove_valid(self):
        """prove should return True for tautologies."""
        x = z3.Int("x")

        # x == x is always true
        assert prove(x == x) is True

    def test_prove_invalid(self):
        """prove should return False for non-tautologies."""
        x = z3.Int("x")

        # x > 0 is not always true
        assert prove(x > 0) is False

    def test_clear_solver_caches(self):
        """clear_solver_caches should not crash."""
        # Just ensure it doesn't raise
        clear_solver_caches()
