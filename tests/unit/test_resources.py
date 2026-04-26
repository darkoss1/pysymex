"""Tests for pysymex.resources — resource management and limits."""

from __future__ import annotations

import pytest

from pysymex.resources import (
    AnalysisTimeoutError,
    GracefulDegradation,
    LimitExceeded,
    PartialResult,
    ResourceLimits,
    ResourceSnapshot,
    ResourceTracker,
    ResourceType,
    create_partial_result,
)


class TestResourceType:
    """Tests for the ResourceType enumeration."""

    def test_all_members_exist(self) -> None:
        """All expected resource types are defined."""
        assert ResourceType.PATHS.name == "PATHS"
        assert ResourceType.DEPTH.name == "DEPTH"
        assert ResourceType.ITERATIONS.name == "ITERATIONS"
        assert ResourceType.TIME.name == "TIME"
        assert ResourceType.MEMORY.name == "MEMORY"
        assert ResourceType.CONSTRAINTS.name == "CONSTRAINTS"

    def test_members_are_distinct(self) -> None:
        """All enum members have unique values."""
        values = [m.value for m in ResourceType]
        assert len(values) == len(set(values))


class TestLimitExceeded:
    """Tests for the LimitExceeded exception."""

    def test_init_stores_fields(self) -> None:
        """Constructor stores resource_type, current, and limit."""
        exc = LimitExceeded(ResourceType.PATHS, 1001, 1000)
        assert exc.resource_type == ResourceType.PATHS
        assert exc.current == 1001
        assert exc.limit == 1000

    def test_message_contains_resource_name(self) -> None:
        """Error message includes the resource type name."""
        exc = LimitExceeded(ResourceType.DEPTH, 101, 100)
        assert "DEPTH" in str(exc)

    def test_is_exception(self) -> None:
        """LimitExceeded is catchable as Exception."""
        assert isinstance(LimitExceeded(ResourceType.TIME, 61.0, 60.0), Exception)


class TestAnalysisTimeoutError:
    """Tests for AnalysisTimeoutError."""

    def test_is_limit_exceeded(self) -> None:
        """AnalysisTimeoutError is a subclass of LimitExceeded."""
        assert isinstance(AnalysisTimeoutError(65.0, 60.0), LimitExceeded)

    def test_resource_type_is_time(self) -> None:
        """resource_type is always TIME."""
        assert AnalysisTimeoutError(120.0, 60.0).resource_type == ResourceType.TIME

    def test_stores_elapsed_and_limit(self) -> None:
        """current holds elapsed time, limit holds the cap."""
        exc = AnalysisTimeoutError(70.5, 60.0)
        assert exc.current == 70.5
        assert exc.limit == 60.0


class TestResourceSnapshot:
    """Tests for the ResourceSnapshot dataclass."""

    def test_defaults(self) -> None:
        """Default snapshot has all zeroes."""
        snap = ResourceSnapshot()
        assert snap.paths_explored == 0
        assert snap.elapsed_time == 0.0

    def test_to_dict_keys(self) -> None:
        """to_dict returns all expected keys."""
        d = ResourceSnapshot().to_dict()
        expected = {
            "paths_explored",
            "current_depth",
            "max_depth_reached",
            "iterations",
            "elapsed_time",
            "memory_mb",
            "avg_memory_mb",
            "constraint_count",
            "solver_calls",
            "cache_hits",
            "cache_misses",
        }
        assert set(d.keys()) == expected

    def test_to_dict_values_match(self) -> None:
        """to_dict values match constructor args."""
        snap = ResourceSnapshot(paths_explored=42, iterations=100)
        d = snap.to_dict()
        assert d["paths_explored"] == 42
        assert d["iterations"] == 100

    def test_frozen(self) -> None:
        """ResourceSnapshot is frozen."""
        with pytest.raises(AttributeError):
            ResourceSnapshot().paths_explored = 5  # type: ignore[misc]


class TestResourceLimits:
    """Tests for the ResourceLimits dataclass."""

    def test_defaults(self) -> None:
        """Default limits have sensible values."""
        lim = ResourceLimits()
        assert lim.max_paths == 1000
        assert lim.timeout_seconds == 60.0

    def test_to_dict(self) -> None:
        """to_dict has all limit fields."""
        d = ResourceLimits().to_dict()
        assert "max_paths" in d
        assert len(d) == 8

    def test_frozen(self) -> None:
        """ResourceLimits is frozen."""
        with pytest.raises(AttributeError):
            ResourceLimits().max_paths = 999  # type: ignore[misc]


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
        """memory_usage_mb returns a non-negative float."""
        assert ResourceTracker().memory_usage_mb >= 0.0

    def test_add_warning_callback(self) -> None:
        """add_warning_callback registers a callback."""
        t = ResourceTracker()
        t.add_warning_callback(lambda rt, c, l: None)
        assert len(t._warning_callbacks) == 1

    def test_soft_limit_triggers_callback(self) -> None:
        """Soft path limit triggers warning callback."""
        t = ResourceTracker(ResourceLimits(max_paths=10, soft_path_ratio=0.5))
        warnings: list[ResourceType] = []
        t.add_warning_callback(lambda rt, c, l: warnings.append(rt))
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


class TestGracefulDegradation:
    """Tests for the GracefulDegradation class."""

    def test_should_skip_path_not_degraded(self) -> None:
        """Non-degraded tracker does not skip paths."""
        assert GracefulDegradation(ResourceTracker()).should_skip_path(100) is False

    def test_should_skip_path_when_degraded(self) -> None:
        """Degraded tracker skips high-complexity paths."""
        t = ResourceTracker()
        t.enter_degraded_mode("test")
        assert GracefulDegradation(t).should_skip_path(100) is True

    def test_should_skip_path_low_complexity_when_degraded(self) -> None:
        """Degraded tracker does not skip low-complexity paths."""
        t = ResourceTracker()
        t.enter_degraded_mode("test")
        assert GracefulDegradation(t).should_skip_path(5) is False

    def test_should_approximate_constraint(self) -> None:
        """should_approximate_constraint returns bool."""
        t = ResourceTracker()
        t.start()
        assert isinstance(GracefulDegradation(t).should_approximate_constraint(), bool)

    def test_should_stop_early_no_limits(self) -> None:
        """No limits exceeded means don't stop early."""
        t = ResourceTracker()
        t.start()
        assert GracefulDegradation(t).should_stop_early() is False

    def test_should_stop_early_limits_exceeded(self) -> None:
        """Exceeded limits trigger early stop."""
        t = ResourceTracker(ResourceLimits(max_iterations=1))
        t.start()
        t.record_iteration()
        assert GracefulDegradation(t).should_stop_early() is True

    def test_get_active_strategies_empty(self) -> None:
        """Initially no strategies are active."""
        assert GracefulDegradation(ResourceTracker()).get_active_strategies() == []

    def test_activate_strategy(self) -> None:
        """activate_strategy adds a strategy."""
        gd = GracefulDegradation(ResourceTracker())
        gd.activate_strategy("skip_deep_paths")
        assert "skip_deep_paths" in gd.get_active_strategies()

    def test_activate_strategy_no_duplicates(self) -> None:
        """Activating the same strategy twice does not duplicate."""
        gd = GracefulDegradation(ResourceTracker())
        gd.activate_strategy("x")
        gd.activate_strategy("x")
        assert gd.get_active_strategies().count("x") == 1


class TestPartialResult:
    """Tests for the PartialResult dataclass."""

    def test_defaults(self) -> None:
        """Default PartialResult is incomplete."""
        pr = PartialResult()
        assert pr.completed is False and pr.reason is None

    def test_to_dict_keys(self) -> None:
        """to_dict has expected keys."""
        d = PartialResult().to_dict()
        assert "completed" in d and "resources" in d

    def test_to_dict_with_snapshot(self) -> None:
        """to_dict includes resource snapshot when present."""
        pr = PartialResult(resource_snapshot=ResourceSnapshot(paths_explored=10))
        assert isinstance(pr.to_dict()["resources"], dict)

    def test_to_dict_without_snapshot(self) -> None:
        """to_dict has None resources when no snapshot."""
        assert PartialResult().to_dict()["resources"] is None

    def test_issues_found_count(self) -> None:
        """to_dict reports count of issues."""
        assert PartialResult(issues_found=["a", "b"]).to_dict()["issues_found"] == 2


def test_create_partial_result_completed() -> None:
    """create_partial_result with no error marks completed."""
    t = ResourceTracker()
    t.start()
    t.record_path()
    r = create_partial_result(t, ["issue1"])
    assert r.completed is True and r.resource_snapshot is not None


def test_create_partial_result_with_limit_error() -> None:
    """create_partial_result with LimitExceeded stores reason."""
    t = ResourceTracker()
    t.start()
    r = create_partial_result(t, [], LimitExceeded(ResourceType.PATHS, 1001, 1000))
    assert r.completed is False and "PATHS" in (r.reason or "")


def test_create_partial_result_with_generic_error() -> None:
    """create_partial_result with generic exception stores str(error)."""
    t = ResourceTracker()
    t.start()
    r = create_partial_result(t, [], RuntimeError("broke"))
    assert r.completed is False and "broke" in (r.reason or "")
