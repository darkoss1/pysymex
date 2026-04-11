import z3

import pysymex.core.optimization as mod
from pysymex.core.state import VMState


class TestCacheStats:
    def test_hit_rate(self) -> None:
        stats = mod.CacheStats(hits=1, misses=1)
        assert stats.hit_rate == 50.0


class TestConstraintCache:
    def test_get(self) -> None:
        cache = mod.ConstraintCache(max_size=4)
        constraints = [z3.Bool("c")]
        cache.put(constraints, True, None, 0.1)
        assert cache.get(constraints) is not None

    def test_put(self) -> None:
        cache = mod.ConstraintCache(max_size=1)
        cache.put([z3.Bool("a")], True, None, 0.1)
        assert len(cache) == 1

    def test_clear(self) -> None:
        cache = mod.ConstraintCache(max_size=2)
        cache.put([z3.Bool("a")], True, None, 0.1)
        cache.clear()
        assert len(cache) == 0


def test_get_constraint_cache() -> None:
    cache = mod.get_constraint_cache()
    assert isinstance(cache, mod.ConstraintCache)


def test_cached_is_satisfiable() -> None:
    assert mod.cached_is_satisfiable([z3.BoolVal(True)])


class TestMergeStats:
    def test_initialization(self) -> None:
        stats = mod.MergeStats()
        assert stats.merges_attempted == 0


class TestStateMerger:
    def test_compute_state_signature(self) -> None:
        merger = mod.StateMerger()
        sig = merger.compute_state_signature(VMState())
        assert isinstance(sig, tuple)

    def test_states_are_similar(self) -> None:
        merger = mod.StateMerger()
        assert merger.states_are_similar(VMState(), VMState())

    def test_merge_states(self) -> None:
        merger = mod.StateMerger()
        merged = merger.merge_states(VMState(), VMState())
        assert merged is not None

    def test_reduce_state_set(self) -> None:
        merger = mod.StateMerger()
        reduced = merger.reduce_state_set([VMState(), VMState()])
        assert len(reduced) >= 1


class TestLazySymbolicValue:
    def test_value(self) -> None:
        lazy = mod.LazySymbolicValue("x", lambda: 7)
        assert lazy.value == 7

    def test_is_evaluated(self) -> None:
        lazy = mod.LazySymbolicValue("x", lambda: 7)
        assert not lazy.is_evaluated()


class TestCompactState:
    def test_pc(self) -> None:
        state = mod.CompactState(pc=3)
        assert state.pc == 3

    def test_stack(self) -> None:
        state = mod.CompactState(stack=(1, 2))
        assert state.stack == (1, 2)

    def test_locals(self) -> None:
        state = mod.CompactState(locals_=frozenset({("x", 1)}))
        assert state.locals["x"] == 1

    def test_constraints(self) -> None:
        state = mod.CompactState(constraints=(z3.BoolVal(True),))
        assert len(state.constraints) == 1

    def test_with_pc(self) -> None:
        state = mod.CompactState().with_pc(4)
        assert state.pc == 4

    def test_with_push(self) -> None:
        state = mod.CompactState().with_push(1)
        assert state.stack[-1] == 1

    def test_with_pop(self) -> None:
        state, value = mod.CompactState(stack=(1,)).with_pop()
        assert value == 1 and state.stack == ()

    def test_with_local(self) -> None:
        state = mod.CompactState().with_local("x", 1)
        assert state.locals["x"] == 1

    def test_with_constraint(self) -> None:
        state = mod.CompactState().with_constraint(z3.BoolVal(True))
        assert len(state.constraints) == 1


class TestProfileData:
    def test_format_report(self) -> None:
        report = mod.ProfileData().format_report()
        assert "Performance Report" in report


class TestExecutionProfiler:
    def test_start(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.start()
        assert profiler.data.total_time_seconds == 0.0

    def test_stop(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.start()
        profiler.stop()
        assert profiler.data.total_time_seconds >= 0.0

    def test_start_opcode(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.start_opcode("NOP")
        assert profiler.data.opcode_counts == {}

    def test_stop_opcode(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.start_opcode("NOP")
        profiler.stop_opcode()
        assert profiler.data.opcode_counts.get("NOP", 0) == 1

    def test_record_solver_time(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.record_solver_time(0.5)
        assert profiler.data.solver_time_seconds == 0.5

    def test_record_state(self) -> None:
        profiler = mod.ExecutionProfiler()
        profiler.record_state(VMState())
        assert profiler.data.states_created == 1

    def test_get_report(self) -> None:
        profiler = mod.ExecutionProfiler()
        assert "Performance Report" in profiler.get_report()
