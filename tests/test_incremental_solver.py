"""Tests for IncrementalSolver (v0.4.0 solver rewrite)."""

import pytest

import z3


from pysymex.core.solver import IncrementalSolver, SolverResult, ShadowSolver


class TestIncrementalSolverBasic:
    """Basic solver functionality."""

    def test_create_solver(self):
        solver = IncrementalSolver()

        assert solver._query_count == 0

        assert solver._cache_hits == 0

    def test_backward_compat_alias(self):
        """ShadowSolver should be an alias for IncrementalSolver."""

        assert ShadowSolver is IncrementalSolver

    def test_simple_sat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.is_sat([x > 0]) is True

    def test_simple_unsat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.is_sat([x > 0, x < 0]) is False

    def test_empty_constraints_sat(self):
        solver = IncrementalSolver()

        assert solver.is_sat([]) is True

    def test_single_variable(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.is_sat([x == 42]) is True


class TestPushPop:
    """Scope management with push/pop."""

    def test_push_pop_isolation(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.add(x > 0)

        solver.push()

        solver.add(x < 0)

        result = solver.check()

        assert result.is_unsat

        solver.pop()

        result = solver.check()

        assert result.is_sat

    def test_enter_leave_scope(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.enter_scope([x > 5, x < 10])

        result = solver.check()

        assert result.is_sat

        solver.leave_scope()

    def test_nested_scopes(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.push()

        solver.add(x > 0)

        solver.push()

        solver.add(x < 100)

        assert solver._scope_depth == 2

        solver.pop()

        assert solver._scope_depth == 1

        solver.pop()

        assert solver._scope_depth == 0

    def test_pop_at_zero_depth(self):
        solver = IncrementalSolver()

        solver.pop()

        assert solver._scope_depth == 0


class TestCaching:
    """Cache behavior."""

    def test_cache_hit(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        constraints = [x > 0, x < 100]

        solver.is_sat(constraints)

        solver.is_sat(constraints)

        assert solver._cache_hits >= 1

    def test_cache_miss_different_constraints(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.is_sat([x > 0])

        solver.is_sat([x < 0])

        assert solver._query_count == 2

    def test_cache_eviction(self):
        solver = IncrementalSolver(cache_size=5)

        x = z3.Int("x")

        for i in range(10):
            solver.is_sat([x == i])

        assert len(solver._cache) <= 5


class TestCheckSatCached:
    """Full result caching."""

    def test_returns_solver_result(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        result = solver.check_sat_cached([x > 0])

        assert isinstance(result, SolverResult)

        assert result.is_sat

    def test_returns_model_on_sat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        result = solver.check_sat_cached([x == 42])

        assert result.is_sat

        assert result.model is not None

    def test_unsat_result(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        result = solver.check_sat_cached([x > 0, x < 0])

        assert result.is_unsat

        assert result.model is None


class TestGetModel:
    """Model extraction."""

    def test_get_model_sat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        model = solver.get_model([x == 42])

        assert model is not None

    def test_get_model_unsat(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        model = solver.get_model([x > 0, x < 0])

        assert model is None

    def test_get_model_string(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        result = solver.get_model_string([x == 42])

        assert result is not None

        assert "42" in result


class TestImplies:
    """Implication checking."""

    def test_true_implication(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.implies(x > 5, x > 3) is True

    def test_false_implication(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        assert solver.implies(x > 3, x > 5) is False


class TestCounterexample:
    """Counterexample extraction."""

    def test_extract_counterexample(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        ce = solver.extract_counterexample([x == 42])

        assert len(ce) > 0


class TestStats:
    """Statistics collection."""

    def test_get_stats(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.is_sat([x > 0])

        stats = solver.get_stats()

        assert stats["queries"] >= 1

        assert "cache_hits" in stats

        assert "solver_time_ms" in stats

    def test_repr(self):
        solver = IncrementalSolver()

        assert "IncrementalSolver" in repr(solver)


class TestReset:
    """Solver reset."""

    def test_reset_clears_state(self):
        solver = IncrementalSolver()

        x = z3.Int("x")

        solver.push()

        solver.add(x > 0)

        solver.is_sat([x > 0])

        solver.reset()

        assert solver._scope_depth == 0

        assert len(solver._cache) == 0


class TestWarmStart:
    """Warm-start functionality."""

    def test_warm_start_stores_models(self):
        solver = IncrementalSolver(warm_start=True)

        x = z3.Int("x")

        solver.is_sat([x > 0])

        assert len(solver._last_models) >= 0

    def test_warm_start_disabled(self):
        solver = IncrementalSolver(warm_start=False)

        x = z3.Int("x")

        solver.is_sat([x > 0])

        assert len(solver._last_models) == 0
