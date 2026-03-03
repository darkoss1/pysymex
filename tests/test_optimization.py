"""Tests for performance optimization utilities."""

import pytest

import z3


from pysymex.core.optimization import (
    CacheStats,
    ConstraintCache,
    get_constraint_cache,
    cached_is_satisfiable,
    MergeStats,
    StateMerger,
    LazySymbolicValue,
    CompactState,
    ProfileData,
    ExecutionProfiler,
)


class TestConstraintCache:
    """Tests for constraint caching."""

    def test_cache_stats_initial(self):
        """Test initial cache stats."""

        stats = CacheStats()

        assert stats.hits == 0

        assert stats.misses == 0

        assert stats.hit_rate == 0.0

    def test_cache_stats_hit_rate(self):
        """Test cache hit rate calculation."""

        stats = CacheStats(hits=80, misses=20)

        assert stats.hit_rate == 80.0

    def test_constraint_cache_creation(self):
        """Test ConstraintCache creation."""

        cache = ConstraintCache(max_size=100)

        assert cache.max_size == 100

        assert len(cache) == 0

    def test_constraint_cache_put_get(self):
        """Test putting and getting from cache."""

        cache = ConstraintCache()

        x = z3.Int("x")

        constraints = [x > 0, x < 10]

        cache.put(constraints, True, None, 5.0)

        result = cache.get(constraints)

        assert result is not None

        assert result[0] is True

    def test_constraint_cache_miss(self):
        """Test cache miss."""

        cache = ConstraintCache()

        x = z3.Int("x")

        constraints = [x > 0]

        result = cache.get(constraints)

        assert result is None

        assert cache.stats.misses == 1

    def test_constraint_cache_eviction(self):
        """Test cache eviction at capacity."""

        cache = ConstraintCache(max_size=2)

        x = z3.Int("x")

        cache.put([x > 0], True, None, 1.0)

        cache.put([x > 1], True, None, 1.0)

        cache.put([x > 2], True, None, 1.0)

        assert len(cache) == 2

        assert cache.stats.evictions == 1

    def test_cached_is_satisfiable(self):
        """Test cached satisfiability check."""

        cache = ConstraintCache()

        x = z3.Int("x")

        constraints = [x > 0, x < 10]

        result1 = cached_is_satisfiable(constraints, cache)

        assert result1 is True

        assert cache.stats.misses == 1

        result2 = cached_is_satisfiable(constraints, cache)

        assert result2 is True

        assert cache.stats.hits == 1


class TestStateMerger:
    """Tests for state merging."""

    def test_merge_stats_initial(self):
        """Test initial merge stats."""

        stats = MergeStats()

        assert stats.merges_attempted == 0

        assert stats.merges_successful == 0

    def test_state_merger_creation(self):
        """Test StateMerger creation."""

        merger = StateMerger(similarity_threshold=0.9)

        assert merger.similarity_threshold == 0.9


class TestLazySymbolicValue:
    """Tests for lazy symbolic values."""

    def test_lazy_value_not_evaluated(self):
        """Test that lazy value is not evaluated initially."""

        factory_called = [False]

        def factory():
            factory_called[0] = True

            return z3.Int("x")

        lazy = LazySymbolicValue("x", factory)

        assert not lazy.is_evaluated()

        assert not factory_called[0]

    def test_lazy_value_evaluated_on_access(self):
        """Test that lazy value is evaluated on access."""

        def factory():
            return z3.Int("x")

        lazy = LazySymbolicValue("x", factory)

        value = lazy.value

        assert lazy.is_evaluated()

        assert value is not None

    def test_lazy_value_cached(self):
        """Test that lazy value is cached after evaluation."""

        call_count = [0]

        def factory():
            call_count[0] += 1

            return z3.Int("x")

        lazy = LazySymbolicValue("x", factory)

        _ = lazy.value

        _ = lazy.value

        _ = lazy.value

        assert call_count[0] == 1


class TestCompactState:
    """Tests for compact state representation."""

    def test_compact_state_creation(self):
        """Test CompactState creation."""

        state = CompactState(pc=10)

        assert state.pc == 10

        assert state.stack == ()

        assert state.locals == {}

    def test_compact_state_with_pc(self):
        """Test updating PC."""

        state = CompactState(pc=0)

        new_state = state.with_pc(10)

        assert state.pc == 0

        assert new_state.pc == 10

    def test_compact_state_with_push(self):
        """Test pushing to stack."""

        state = CompactState()

        new_state = state.with_push(42)

        assert state.stack == ()

        assert new_state.stack == (42,)

    def test_compact_state_with_pop(self):
        """Test popping from stack."""

        state = CompactState(stack=(1, 2, 3))

        new_state, value = state.with_pop()

        assert value == 3

        assert new_state.stack == (1, 2)

        assert state.stack == (1, 2, 3)

    def test_compact_state_with_local(self):
        """Test setting local variable."""

        state = CompactState()

        new_state = state.with_local("x", 42)

        assert state.locals == {}

        assert new_state.locals == {"x": 42}

    def test_compact_state_with_constraint(self):
        """Test adding constraint."""

        x = z3.Int("x")

        state = CompactState()

        new_state = state.with_constraint(x > 0)

        assert len(state.constraints) == 0

        assert len(new_state.constraints) == 1


class TestExecutionProfiler:
    """Tests for execution profiler."""

    def test_profile_data_creation(self):
        """Test ProfileData creation."""

        data = ProfileData()

        assert data.total_time_seconds == 0.0

        assert data.solver_time_seconds == 0.0

    def test_profiler_start_stop(self):
        """Test profiler start/stop."""

        profiler = ExecutionProfiler()

        profiler.start()

        profiler.stop()

        assert profiler.data.total_time_seconds >= 0

    def test_profiler_opcode_timing(self):
        """Test opcode timing."""

        profiler = ExecutionProfiler()

        profiler.start_opcode("LOAD_FAST")

        profiler.stop_opcode()

        assert "LOAD_FAST" in profiler.data.opcode_counts

        assert profiler.data.opcode_counts["LOAD_FAST"] == 1

    def test_profiler_report(self):
        """Test profiler report generation."""

        profiler = ExecutionProfiler()

        profiler.data.total_time_seconds = 1.0

        profiler.data.solver_time_seconds = 0.5

        profiler.data.paths_explored = 10

        report = profiler.get_report()

        assert "Performance Report" in report

        assert "1.000s" in report

        assert "50.0%" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
