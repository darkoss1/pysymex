"""Tests for pysymex.tracing.tracer.factory — attach_tracer factory helper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
from pysymex.tracing.tracer.factory import attach_tracer
from pysymex.tracing.schemas import TracerConfig


def test_attach_tracer_disabled() -> None:
    """attach_tracer with disabled config installs safely and returns tracer."""
    executor = MagicMock()
    config = TracerConfig(enabled=False)
    tracer, path = attach_tracer(executor, "test_func", config=config)
    assert tracer is not None
    assert path == Path(".pysymex/traces")
