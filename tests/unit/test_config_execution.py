"""Tests for execution configuration rollout fields."""

from __future__ import annotations

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode


def test_execution_config_defaults_to_polar_cegis_runtime_frontier_mode() -> None:
    """Default execution uses resident POLAR/CEGIS runtime frontier mode."""
    config = ExecutionConfig()

    assert config.frontier_runtime_mode is FrontierRuntimeMode.POLAR_CEGIS_RUNTIME


def test_execution_config_defaults_to_automatic_host_limits() -> None:
    config = ExecutionConfig()

    assert config.max_paths is None
    assert config.max_depth is None
    assert config.max_iterations is None
    assert config.timeout_seconds is None


def test_execution_config_accepts_path_overrides() -> None:
    config = ExecutionConfig(max_paths=123)

    assert config.max_paths == 123
