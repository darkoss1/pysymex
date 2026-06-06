"""Tests for execution configuration rollout fields."""

from __future__ import annotations

from pysymex.execution.config.settings import ExecutionConfig, FrontierRuntimeMode


def test_execution_config_defaults_to_polar_cegis_runtime_frontier_mode() -> None:
    """Default execution uses resident POLAR/CEGIS runtime frontier mode."""
    config = ExecutionConfig()

    assert config.frontier_runtime_mode is FrontierRuntimeMode.POLAR_CEGIS_RUNTIME
