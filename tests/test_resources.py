"""Tests for resource management."""

import pytest

import time


from pysymex.resources import (
    ResourceType,
    LimitExceeded,
    TimeoutError,
    ResourceSnapshot,
    ResourceLimits,
    ResourceTracker,
    GracefulDegradation,
    PartialResult,
    create_partial_result,
)


class TestResourceType:
    """Tests for ResourceType enum."""

    def test_resource_types_exist(self):
        """Test that resource types are defined."""

        assert ResourceType.PATHS is not None

        assert ResourceType.DEPTH is not None

        assert ResourceType.ITERATIONS is not None

        assert ResourceType.TIME is not None

        assert ResourceType.MEMORY is not None


class TestLimitExceeded:
    """Tests for LimitExceeded exception."""

    def test_create_exception(self):
        """Test creating limit exceeded exception."""

        exc = LimitExceeded(ResourceType.PATHS, 1000, 500)

        assert exc.resource_type == ResourceType.PATHS

        assert exc.current == 1000

        assert exc.limit == 500

    def test_exception_message(self):
        """Test exception message."""

        exc = LimitExceeded(ResourceType.TIME, 60, 30)

        assert "TIME" in str(exc)

        assert "60" in str(exc)


class TestTimeoutError:
    """Tests for TimeoutError."""

    def test_create_timeout(self):
        """Test creating timeout error."""

        exc = TimeoutError(elapsed=30.0, limit=20.0)

        assert exc.resource_type == ResourceType.TIME

        assert exc.current == 30.0

        assert exc.limit == 20.0


class TestResourceSnapshot:
    """Tests for ResourceSnapshot."""

    def test_create_snapshot(self):
        """Test creating resource snapshot."""

        snapshot = ResourceSnapshot(
            paths_explored=100,
            current_depth=5,
            iterations=500,
        )

        assert snapshot.paths_explored == 100

        assert snapshot.current_depth == 5

        assert snapshot.iterations == 500

    def test_to_dict(self):
        """Test conversion to dictionary."""

        snapshot = ResourceSnapshot(paths_explored=50)

        d = snapshot.to_dict()

        assert d["paths_explored"] == 50

        assert "elapsed_time" in d

        assert "solver_calls" in d


class TestResourceLimits:
    """Tests for ResourceLimits."""

    def test_default_limits(self):
        """Test default resource limits."""

        limits = ResourceLimits()

        assert limits.max_paths == 1000

        assert limits.max_depth == 100

        assert limits.max_iterations == 10000

        assert limits.timeout_seconds == 60.0

    def test_custom_limits(self):
        """Test custom resource limits."""

        limits = ResourceLimits(
            max_paths=500,
            timeout_seconds=30.0,
        )

        assert limits.max_paths == 500

        assert limits.timeout_seconds == 30.0

    def test_to_dict(self):
        """Test conversion to dictionary."""

        limits = ResourceLimits()

        d = limits.to_dict()

        assert "max_paths" in d

        assert "timeout_seconds" in d


class TestResourceTracker:
    """Tests for ResourceTracker."""

    def test_create_tracker(self):
        """Test creating resource tracker."""

        tracker = ResourceTracker()

        assert tracker is not None

        assert tracker.limits is not None

    def test_start_tracking(self):
        """Test starting resource tracking."""

        tracker = ResourceTracker()

        tracker.start()

        time.sleep(0.01)

        assert tracker.elapsed_time > 0

    def test_record_path(self):
        """Test recording paths."""

        tracker = ResourceTracker()

        count = tracker.record_path()

        assert count == 1

        count = tracker.record_path()

        assert count == 2

    def test_record_iteration(self):
        """Test recording iterations."""

        tracker = ResourceTracker()

        count = tracker.record_iteration()

        assert count == 1

    def test_push_pop_depth(self):
        """Test depth tracking."""

        tracker = ResourceTracker()

        depth = tracker.push_depth()

        assert depth == 1

        depth = tracker.push_depth()

        assert depth == 2

        depth = tracker.pop_depth()

        assert depth == 1

        depth = tracker.pop_depth()

        assert depth == 0

    def test_check_path_limit(self):
        """Test path limit checking."""

        limits = ResourceLimits(max_paths=5)

        tracker = ResourceTracker(limits)

        for _ in range(4):
            tracker.record_path()

        tracker.check_path_limit()

        tracker.record_path()

        with pytest.raises(LimitExceeded) as exc_info:
            tracker.check_path_limit()

        assert exc_info.value.resource_type == ResourceType.PATHS

    def test_check_depth_limit(self):
        """Test depth limit checking."""

        limits = ResourceLimits(max_depth=3)

        tracker = ResourceTracker(limits)

        tracker.push_depth()

        tracker.push_depth()

        tracker.check_depth_limit()

        tracker.push_depth()

        with pytest.raises(LimitExceeded) as exc_info:
            tracker.check_depth_limit()

        assert exc_info.value.resource_type == ResourceType.DEPTH

    def test_check_iteration_limit(self):
        """Test iteration limit checking."""

        limits = ResourceLimits(max_iterations=10)

        tracker = ResourceTracker(limits)

        for _ in range(9):
            tracker.record_iteration()

        tracker.check_iteration_limit()

        tracker.record_iteration()

        with pytest.raises(LimitExceeded) as exc_info:
            tracker.check_iteration_limit()

        assert exc_info.value.resource_type == ResourceType.ITERATIONS

    def test_snapshot(self):
        """Test getting resource snapshot."""

        tracker = ResourceTracker()

        tracker.start()

        tracker.record_path()

        tracker.record_path()

        tracker.push_depth()

        tracker.record_iteration()

        snapshot = tracker.snapshot()

        assert snapshot.paths_explored == 2

        assert snapshot.current_depth == 1

        assert snapshot.iterations == 1

        assert snapshot.elapsed_time >= 0

    def test_solver_call_tracking(self):
        """Test solver call tracking."""

        tracker = ResourceTracker()

        tracker.record_solver_call(cache_hit=False)

        tracker.record_solver_call(cache_hit=True)

        tracker.record_solver_call(cache_hit=False)

        snapshot = tracker.snapshot()

        assert snapshot.solver_calls == 3

        assert snapshot.cache_hits == 1

        assert snapshot.cache_misses == 2

    def test_get_progress(self):
        """Test getting progress percentages."""

        limits = ResourceLimits(max_paths=100, max_depth=50)

        tracker = ResourceTracker(limits)

        for _ in range(25):
            tracker.record_path()

        progress = tracker.get_progress()

        assert progress["paths"] == 25.0

    def test_warning_callback(self):
        """Test soft limit warning callbacks."""

        limits = ResourceLimits(max_paths=10, soft_path_ratio=0.8)

        tracker = ResourceTracker(limits)

        warnings = []

        def on_warning(resource_type, current, limit):
            warnings.append((resource_type, current, limit))

        tracker.add_warning_callback(on_warning)

        for _ in range(7):
            tracker.record_path()

            tracker.check_path_limit()

        assert len(warnings) == 0

        tracker.record_path()

        tracker.check_path_limit()

        assert len(warnings) == 1

        assert warnings[0][0] == ResourceType.PATHS

    def test_degraded_mode(self):
        """Test entering degraded mode."""

        tracker = ResourceTracker()

        assert not tracker.is_degraded

        tracker.enter_degraded_mode("Running low on paths")

        assert tracker.is_degraded


class TestGracefulDegradation:
    """Tests for GracefulDegradation."""

    def test_create_degradation(self):
        """Test creating degradation handler."""

        tracker = ResourceTracker()

        degradation = GracefulDegradation(tracker)

        assert degradation is not None

    def test_should_skip_path(self):
        """Test path skipping decision."""

        tracker = ResourceTracker()

        degradation = GracefulDegradation(tracker)

        assert not degradation.should_skip_path(20)

        tracker.enter_degraded_mode("test")

        assert degradation.should_skip_path(20)

        assert not degradation.should_skip_path(5)

    def test_should_stop_early(self):
        """Test early stopping decision."""

        limits = ResourceLimits(max_paths=5)

        tracker = ResourceTracker(limits)

        degradation = GracefulDegradation(tracker)

        assert not degradation.should_stop_early()

        for _ in range(5):
            tracker.record_path()

        assert degradation.should_stop_early()


class TestPartialResult:
    """Tests for PartialResult."""

    def test_create_partial_result(self):
        """Test creating partial result."""

        result = PartialResult(
            completed=False,
            reason="Timeout",
            paths_completed=50,
        )

        assert not result.completed

        assert result.reason == "Timeout"

        assert result.paths_completed == 50

    def test_to_dict(self):
        """Test conversion to dictionary."""

        result = PartialResult(
            completed=True,
            paths_completed=100,
        )

        d = result.to_dict()

        assert d["completed"] is True

        assert d["paths_completed"] == 100


class TestCreatePartialResult:
    """Tests for create_partial_result helper."""

    def test_create_from_tracker(self):
        """Test creating partial result from tracker."""

        tracker = ResourceTracker()

        tracker.start()

        tracker.record_path()

        tracker.record_path()

        issues = [{"type": "test", "message": "Test issue"}]

        result = create_partial_result(tracker, issues)

        assert result.completed is True

        assert result.paths_completed == 2

        assert len(result.issues_found) == 1

    def test_create_from_error(self):
        """Test creating partial result from error."""

        tracker = ResourceTracker()

        tracker.record_path()

        error = LimitExceeded(ResourceType.PATHS, 100, 50)

        result = create_partial_result(tracker, [], error)

        assert not result.completed

        assert "PATHS" in result.reason
