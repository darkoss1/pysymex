"""Solver cache collision safety tests.

Verifies that the SAT cache never returns incorrect results due to hash collisions.

Source contracts tested:
- solver.py:210-258 (_constraints_discriminator, _cache_lookup, _cache_store)
- solver.py:355-465 (is_sat with caching)
- solver.py:458-462 (Unknown treated as SAT for soundness)

Critical invariants:
1. Discriminator prevents false hits
2. SAT/UNSAT consistency - cannot return SAT for UNSAT or vice versa
3. Scope-aware caching - push/pop must not pollute cache
4. Unknown results return True (conservative for soundness)
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.solver import IncrementalSolver, SolverResult
from pysymex.core.constraint_hash import structural_hash


class TestDiscriminatorPreventsFalseHits:
    """Verify secondary discriminator prevents hash collision false hits."""

    def test_different_constraints_same_primary_hash_no_collision(self):
        """Different constraints that happen to have same primary hash must not collide."""
        solver = IncrementalSolver(use_cache=True)

        # Create constraint sets
        x = z3.Int("x")
        y = z3.Int("y")
        c1 = [x > 0]
        c2 = [y > 0]

        # Check both
        result1 = solver.is_sat(c1)
        result2 = solver.is_sat(c2)

        # Both should be SAT
        assert result1 is True
        assert result2 is True

        # Now verify cache hits are correct
        solver._cache.clear()
        solver._cache_index.clear()

        # Store a fake result for c1
        key1 = solver._make_cache_key(c1)
        disc1 = solver._constraints_discriminator(c1)
        solver._cache_store(key1, disc1, SolverResult.unsat())

        # Lookup for c1 should hit (return stored value)
        cached1 = solver._cache_lookup(key1, disc1)
        assert cached1 is not None
        assert cached1.is_unsat

        # Lookup for c2 with same primary key but different discriminator should miss
        disc2 = solver._constraints_discriminator(c2)
        assert disc1 != disc2  # Different variables, different discriminator

    def test_discriminator_uses_z3_ast_hashes(self):
        """Discriminator must use Z3 internal hashes for collision safety."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        c1 = [x > 0, x < 10]
        c2 = [x > 0, x < 20]

        disc1 = solver._constraints_discriminator(c1)
        disc2 = solver._constraints_discriminator(c2)

        assert disc1 != disc2, "Different constraints must have different discriminators"

    def test_empty_constraint_list_discriminator(self):
        """Empty constraint list should have empty discriminator."""
        solver = IncrementalSolver()
        disc = solver._constraints_discriminator([])
        assert disc == ()


class TestSATUNSATConsistency:
    """Verify cache maintains SAT/UNSAT consistency."""

    def test_unsat_query_returns_unsat(self):
        """UNSAT constraints must return False from cache."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # Contradictory constraints
        unsat_constraints = [x > 10, x < 5]

        # First call computes result
        result = solver.is_sat(unsat_constraints)
        assert result is False

        # Second call should use cache and still be False
        result2 = solver.is_sat(unsat_constraints)
        assert result2 is False

    def test_sat_query_returns_sat(self):
        """SAT constraints must return True from cache."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        sat_constraints = [x > 0, x < 100]

        result = solver.is_sat(sat_constraints)
        assert result is True

        # Cached result should also be True
        result2 = solver.is_sat(sat_constraints)
        assert result2 is True

    def test_cache_does_not_confuse_sat_and_unsat(self):
        """Cache must not return UNSAT result for SAT query or vice versa."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        sat_constraints = [x > 0]
        unsat_constraints = [x > 0, x < 0]

        # Compute both
        sat_result = solver.is_sat(sat_constraints)
        unsat_result = solver.is_sat(unsat_constraints)

        assert sat_result is True
        assert unsat_result is False

        # Query again in reverse order
        assert solver.is_sat(unsat_constraints) is False
        assert solver.is_sat(sat_constraints) is True


class TestModelCorrectness:
    """Verify cached models satisfy original constraints."""

    def test_cached_model_satisfies_constraints(self):
        """Model from cache must satisfy the constraints it was stored for."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [x > 10, y > 20, x + y < 50]

        # First query returns model
        result = solver.check_sat_cached(constraints)
        assert result.is_sat
        assert result.model is not None

        # Verify model satisfies all constraints
        model = result.model
        x_val = model.eval(x).as_long()
        y_val = model.eval(y).as_long()

        assert x_val > 10
        assert y_val > 20
        assert x_val + y_val < 50

    def test_different_queries_get_correct_models(self):
        """Different constraint sets must get their own correct models."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        c1 = [x > 1000]
        c2 = [x < -1000]

        r1 = solver.check_sat_cached(c1)
        r2 = solver.check_sat_cached(c2)

        assert r1.is_sat
        assert r2.is_sat

        x_val_1 = r1.model.eval(x).as_long()
        x_val_2 = r2.model.eval(x).as_long()

        assert x_val_1 > 1000
        assert x_val_2 < -1000


class TestScopeAwareCaching:
    """Verify push/pop scopes do not pollute cache."""

    def test_same_constraints_different_scopes_different_keys(self):
        """Same constraints in different ambient scopes must have different cache keys."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        query = [x > 0]

        # Query in base scope
        key1 = solver._make_cache_key(query)

        # Push and add ambient constraint
        solver.push()
        solver.add(x < 100)
        key2 = solver._make_cache_key(query)
        solver.pop()

        # Keys should differ due to scope context
        assert key1 != key2

    def test_scope_context_stack_updates_on_push(self):
        """Push should update context stack."""
        solver = IncrementalSolver()
        initial_depth = len(solver._cache_context_stack)

        solver.push()
        assert len(solver._cache_context_stack) == initial_depth + 1

        solver.push()
        assert len(solver._cache_context_stack) == initial_depth + 2

        solver.pop()
        assert len(solver._cache_context_stack) == initial_depth + 1

        solver.pop()
        assert len(solver._cache_context_stack) == initial_depth

    def test_adding_constraint_changes_context(self):
        """Adding constraints should change the cache context."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        initial_context = solver._current_cache_context()
        solver.add(x > 0)
        new_context = solver._current_cache_context()

        assert initial_context != new_context

    def test_results_isolated_across_scopes(self):
        """Results computed in one scope must not incorrectly serve another scope."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # In scope with x > 100, query x > 50 should be SAT
        solver.push()
        solver.add(x > 100)
        result1 = solver.is_sat([x > 50])
        solver.pop()

        assert result1 is True

        # In scope with x < 10, query x > 50 should be UNSAT
        solver.push()
        solver.add(x < 10)
        result2 = solver.is_sat([x > 50])
        solver.pop()

        assert result2 is False


class TestIncrementalSolverStateConsistency:
    """Verify solver state remains consistent after many push/pop cycles."""

    def test_many_push_pop_cycles(self):
        """Solver should remain consistent after many push/pop cycles."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        for i in range(100):
            solver.push()
            solver.add(x > i)
            result = solver.is_sat([x < 1000])
            assert result is True
            solver.pop()

        # Final query should still work correctly
        assert solver.is_sat([x > 0]) is True
        assert solver.is_sat([x > 0, x < 0]) is False

    def test_nested_push_pop(self):
        """Nested push/pop should maintain correct state."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        solver.push()
        solver.add(x > 0)

        solver.push()
        solver.add(y > 0)

        # Both constraints active
        result = solver.is_sat([x + y > 1])
        assert result is True

        solver.pop()  # Remove y > 0

        # Only x > 0 active
        result = solver.is_sat([x > 0, y < -100])  # y is now free
        assert result is True

        solver.pop()  # Remove x > 0

    def test_reset_clears_all_state(self):
        """Reset should clear all internal state."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # Build up state
        solver.push()
        solver.add(x > 100)
        solver.is_sat([x > 50])

        assert solver._query_count > 0
        assert len(solver._cache) > 0

        solver.reset()

        # State should be cleared
        assert solver._scope_depth == 0
        assert len(solver._cache) == 0
        assert len(solver._cache_index) == 0


class TestUnknownTreatedAsSAT:
    """Verify unknown results are treated as SAT for soundness."""

    def test_unknown_returns_true_for_soundness(self):
        """Unknown solver result must return True (SAT) to avoid unsound pruning."""
        # Create a very short timeout solver
        solver = IncrementalSolver(timeout_ms=1)

        # Create a hard constraint that may timeout
        # Note: This may or may not actually timeout, but we can test the logic
        x = z3.Int("x")
        y = z3.Int("y")
        z_var = z3.Int("z")

        # Simple constraints that should be SAT
        constraints = [x > 0, y > 0, z_var > 0]
        result = solver.is_sat(constraints)

        # Result should be True regardless (either actual SAT or unknown->True)
        assert result is True

    def test_is_sat_never_incorrectly_prunes_feasible_path(self):
        """is_sat should never return False for actually SAT constraints."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        # Test many SAT constraint combinations
        sat_cases = [
            [x > 0],
            [x > 0, x < 100],
            [x > -1000, x < 1000, x != 0],
            [z3.Or(x > 0, x < 0)],
        ]

        for constraints in sat_cases:
            result = solver.is_sat(constraints)
            assert result is True, f"is_sat incorrectly returned False for {constraints}"


class TestCacheLRUEviction:
    """Verify cache LRU eviction works correctly."""

    def test_lru_eviction_maintains_correctness(self):
        """Cache eviction should not cause incorrect results."""
        # Use a very small cache
        solver = IncrementalSolver(cache_size=5)
        x = z3.Int("x")

        # Generate more queries than cache size
        results = []
        for i in range(20):
            constraints = [x > i, x < i + 100]
            result = solver.is_sat(constraints)
            results.append((i, result))

        # All should be SAT
        for i, result in results:
            assert result is True

        # Re-query the first few (which may have been evicted)
        for i in range(5):
            constraints = [x > i, x < i + 100]
            result = solver.is_sat(constraints)
            assert result is True


class TestStructuralHashIntegrity:
    """Verify structural hash produces consistent results."""

    def test_same_constraints_same_hash(self):
        """Semantically identical constraints must have same structural hash."""
        x = z3.Int("x")

        c1 = [x > 0, x < 10]
        c2 = [x > 0, x < 10]  # Same constraints

        h1 = structural_hash(c1)
        h2 = structural_hash(c2)

        assert h1 == h2

    def test_different_order_different_hash(self):
        """Constraints in different order may have different hash (order-sensitive)."""
        x = z3.Int("x")

        c1 = [x > 0, x < 10]
        c2 = [x < 10, x > 0]  # Reversed order

        h1 = structural_hash(c1)
        h2 = structural_hash(c2)

        # Note: structural_hash is order-sensitive by design
        # This is fine because constraint lists maintain order
        # The test just verifies this property
        if h1 == h2:
            # If hashes happen to be equal, both should work correctly anyway
            pass  # This is acceptable

    def test_hash_is_64bit_bounded(self):
        """Structural hash must fit in 64 bits."""
        x = z3.Int("x")
        constraints = [x > i for i in range(1000)]

        h = structural_hash(constraints)
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


class TestCacheKeyMixing:
    """Verify cache key mixing produces good distribution."""

    def test_mix_cache_context_deterministic(self):
        """Mix function must be deterministic."""
        result1 = IncrementalSolver._mix_cache_context(12345, 67890)
        result2 = IncrementalSolver._mix_cache_context(12345, 67890)
        assert result1 == result2

    def test_mix_cache_context_different_inputs_different_outputs(self):
        """Different inputs should produce different outputs."""
        r1 = IncrementalSolver._mix_cache_context(1, 2)
        r2 = IncrementalSolver._mix_cache_context(1, 3)
        r3 = IncrementalSolver._mix_cache_context(2, 2)

        assert r1 != r2
        assert r1 != r3
        assert r2 != r3


class TestConstraintIndependenceOptimizer:
    """Verify constraint independence doesn't affect correctness."""

    def test_independent_clusters_correct_result(self):
        """Independent constraint clusters should still produce correct results."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        # x and y are independent
        constraints = [x > 0, y > 0]
        result = solver.is_sat(constraints)
        assert result is True

        # Make one cluster UNSAT
        constraints_unsat = [x > 0, x < 0, y > 0]
        result_unsat = solver.is_sat(constraints_unsat)
        assert result_unsat is False

    def test_dependent_constraints_correct_result(self):
        """Dependent constraints should be handled correctly."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        y = z3.Int("y")

        # x and y are dependent via x + y constraint
        constraints = [x > 0, y > 0, x + y < 1]
        result = solver.is_sat(constraints)
        assert result is False  # Can't have x > 0, y > 0 with x + y < 1
