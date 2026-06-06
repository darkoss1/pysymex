"""Tests for pysymex resource tracking."""

from __future__ import annotations

import pytest

from pysymex.resources.models import (
    AnalysisTimeoutError,
    LimitExceeded,
    ResourceLimits,
    ResourceSnapshot,
    ResourceType,
)
from pysymex.resources.tracker import ResourceTracker


class TestResourceTracker:
    """Tests for the ResourceTracker class."""

    def test_init_with_defaults(self) -> None:
        """ResourceTracker initializes with default limits."""
        assert ResourceTracker().limits.max_paths == 1000

    def test_init_with_custom_limits(self) -> None:
        """ResourceTracker accepts custom limits."""
        assert ResourceTracker(ResourceLimits(max_paths=50)).limits.max_paths == 50

    def test_start_sets_time(self) -> None:
        """start() begins time tracking."""
        t = ResourceTracker()
        t.start()
        assert t.elapsed_time >= 0.0

    def test_elapsed_time_before_start(self) -> None:
        """elapsed_time is 0 before start()."""
        assert ResourceTracker().elapsed_time == 0.0

    def test_reset_clears_counters(self) -> None:
        """reset() zeroes all counters."""
        t = ResourceTracker()
        t.start()
        t.record_path()
        t.record_iteration()
        t.reset()
        snap = t.snapshot()
        assert snap.paths_explored == 0
        assert snap.iterations == 0

    def test_snapshot_returns_snapshot(self) -> None:
        """snapshot() returns a ResourceSnapshot."""
        t = ResourceTracker()
        t.start()
        assert isinstance(t.snapshot(), ResourceSnapshot)

    def test_record_path_increments(self) -> None:
        """record_path() increments the path counter."""
        t = ResourceTracker()
        assert t.record_path() == 1
        assert t.record_path() == 2

    def test_record_path_does_not_emit_stats_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """record_path() updates the resource-limit counter without publishing stats."""
        emitted: list[object] = []

        def record_emit(*args: object) -> None:
            emitted.append(args)

        monkeypatch.setattr(
            "pysymex.resources.tracker.emit",
            record_emit,
            raising=False,
        )

        assert ResourceTracker().record_path() == 1
        assert emitted == []

    def test_record_iteration_increments(self) -> None:
        """record_iteration() increments the iteration counter."""
        assert ResourceTracker().record_iteration() == 1

    def test_push_depth(self) -> None:
        """push_depth() increments call depth."""
        t = ResourceTracker()
        assert t.push_depth() == 1
        assert t.push_depth() == 2

    def test_pop_depth(self) -> None:
        """pop_depth() decrements call depth."""
        t = ResourceTracker()
        t.push_depth()
        t.push_depth()
        assert t.pop_depth() == 1

    def test_pop_depth_floor_at_zero(self) -> None:
        """pop_depth() does not go below zero."""
        assert ResourceTracker().pop_depth() == 0

    def test_record_constraint(self) -> None:
        """record_constraint() accumulates count."""
        t = ResourceTracker()
        t.record_constraint(5)
        t.record_constraint(3)
        assert t.snapshot().constraint_count == 8

    def test_record_solver_call_miss(self) -> None:
        """record_solver_call with cache_hit=False increments misses."""
        t = ResourceTracker()
        t.record_solver_call(cache_hit=False)
        snap = t.snapshot()
        assert snap.solver_calls == 1 and snap.cache_misses == 1

    def test_record_solver_call_hit(self) -> None:
        """record_solver_call with cache_hit=True increments hits."""
        t = ResourceTracker()
        t.record_solver_call(cache_hit=True)
        assert t.snapshot().cache_hits == 1

    def test_enter_degraded_mode(self) -> None:
        """enter_degraded_mode sets the degraded flag."""
        t = ResourceTracker()
        assert t.is_degraded is False
        t.enter_degraded_mode("memory pressure")
        assert t.is_degraded is True

    def test_get_progress(self) -> None:
        """get_progress returns percentage dict."""
        t = ResourceTracker()
        t.start()
        p = t.get_progress()
        assert all(k in p for k in ("paths", "depth", "iterations", "time"))

    def test_check_path_limit_raises(self) -> None:
        """check_path_limit raises when limit reached."""
        t = ResourceTracker(ResourceLimits(max_paths=2))
        t.record_path()
        t.record_path()
        with pytest.raises(LimitExceeded):
            t.check_path_limit()

    def test_check_depth_limit_raises(self) -> None:
        """check_depth_limit raises when limit reached."""
        t = ResourceTracker(ResourceLimits(max_depth=2))
        t.push_depth()
        t.push_depth()
        with pytest.raises(LimitExceeded):
            t.check_depth_limit()

    def test_check_iteration_limit_raises(self) -> None:
        """check_iteration_limit raises when limit reached."""
        t = ResourceTracker(ResourceLimits(max_iterations=3))
        for _ in range(3):
            t.record_iteration()
        with pytest.raises(LimitExceeded):
            t.check_iteration_limit()

    def test_check_time_limit_raises(self) -> None:
        """check_time_limit raises AnalysisTimeoutError when expired."""
        t = ResourceTracker(ResourceLimits(timeout_seconds=0.0))
        t.start()
        with pytest.raises(AnalysisTimeoutError):
            t.check_time_limit()

    def test_check_all_limits_depth(self) -> None:
        """check_all_limits detects depth overflow."""
        t = ResourceTracker(ResourceLimits(max_depth=1))
        t.start()
        t.push_depth()
        with pytest.raises(LimitExceeded):
            t.check_all_limits()

    def test_memory_usage_mb_non_negative(self) -> None:
        """memory_usage_mb returns a positive float."""
        assert ResourceTracker().memory_usage_mb > 0.0

    def test_add_warning_callback(self) -> None:
        """add_warning_callback registers a callback."""
        t = ResourceTracker()
        t.add_warning_callback(lambda rt, current, limit: None)
        assert len(t.warning_callbacks) == 1

    def test_soft_limit_triggers_callback(self) -> None:
        """Soft path limit triggers warning callback."""
        t = ResourceTracker(ResourceLimits(max_paths=10, soft_path_ratio=0.5))
        warnings: list[ResourceType] = []
        t.add_warning_callback(lambda rt, current, limit: warnings.append(rt))
        for _ in range(6):
            t.record_path()
        t.check_path_limit()
        assert ResourceType.PATHS in warnings

    def test_max_depth_tracked(self) -> None:
        """Snapshot tracks maximum depth reached."""
        t = ResourceTracker()
        t.push_depth()
        t.push_depth()
        t.push_depth()
        t.pop_depth()
        snap = t.snapshot()
        assert snap.max_depth_reached == 3 and snap.current_depth == 2
