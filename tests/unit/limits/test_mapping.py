"""Tests for host resource limit mapping."""

from __future__ import annotations

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.limits.mapping import limits_from_execution_config
from pysymex._internal.limits.models import ResourceLimits


def test_resource_limits_from_execution_config_uses_engine_defaults_for_extras() -> None:
    config = ExecutionConfig(max_paths=7, max_depth=8, max_iterations=9, timeout_seconds=1.5)
    limits = limits_from_execution_config(config)
    assert limits.max_paths == 7
    assert limits.max_depth == 8
    assert limits.max_iterations == 9
    assert limits.timeout_seconds == 1.5
    assert limits.max_memory_mb == ResourceLimits().max_memory_mb
    assert limits.max_constraints == ResourceLimits().max_constraints
