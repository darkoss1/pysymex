"""Tests for host engine limit domain models."""

from __future__ import annotations

import pytest

from pysymex._internal.limits.models import (
    AnalysisTimeoutError,
    LimitExceeded,
    ResourceLimits,
    ResourceSnapshot,
    ResourceType,
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
        """Default host exploration limits select automatic mode."""
        lim = ResourceLimits()
        assert lim.max_paths is None
        assert lim.max_depth is None
        assert lim.max_iterations is None
        assert lim.timeout_seconds is None

    def test_to_dict(self) -> None:
        """to_dict has all limit fields."""
        d = ResourceLimits().to_dict()
        assert "max_paths" in d
        assert len(d) == 8

    def test_frozen(self) -> None:
        """ResourceLimits is frozen."""
        with pytest.raises(AttributeError):
            ResourceLimits().max_paths = 999  # type: ignore[misc]
