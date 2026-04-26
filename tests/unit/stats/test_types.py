from __future__ import annotations

import time

from pysymex.stats.types import Event, EventType, _new_metadata


class TestTypes:
    """Test suite for stats/types.py."""

    def test_new_metadata_returns_empty_dict(self) -> None:
        """Verify that _new_metadata returns an empty dictionary."""
        metadata = _new_metadata()
        assert metadata == {}
        assert isinstance(metadata, dict)

    def test_event_initialization_with_defaults(self) -> None:
        """Verify that Event initializes correctly with default timestamp and metadata."""
        before = time.perf_counter_ns()
        event = Event(type=EventType.PATH_EXPLORED, value=1.0)
        after = time.perf_counter_ns()

        assert event.type == EventType.PATH_EXPLORED
        assert event.value == 1.0
        assert before <= event.timestamp_ns <= after
        assert event.metadata == {}

    def test_event_initialization_with_explicit_values(self) -> None:
        """Verify that Event initializes correctly with explicit timestamp and metadata."""
        metadata = {"foo": "bar"}
        event = Event(
            type=EventType.SOLVER_SAT,
            value=42.0,
            timestamp_ns=12345,
            metadata=metadata,
        )

        assert event.type == EventType.SOLVER_SAT
        assert event.value == 42.0
        assert event.timestamp_ns == 12345
        assert event.metadata == metadata
