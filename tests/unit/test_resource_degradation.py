"""Tests for pysymex resource degradation results."""

from __future__ import annotations

from pysymex.resources.degradation import (
    GracefulDegradation,
    PartialResult,
    create_partial_result,
)
from pysymex.resources.models import (
    LimitExceeded,
    ResourceLimits,
    ResourceSnapshot,
    ResourceType,
)
from pysymex.resources.tracker import ResourceTracker


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
