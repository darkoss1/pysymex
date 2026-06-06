"""Tests for host resource limit mapping."""

from __future__ import annotations

from pysymex.config import AnalysisLimits, PysymexConfig
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.resources.mapping import (
    analysis_limits_from_resource_limits,
    resource_limits_from_analysis_limits,
    resource_limits_from_execution_config,
)
from pysymex.resources.models import ResourceLimits


def test_resource_limits_from_analysis_limits_maps_constraint_field() -> None:
    profile = AnalysisLimits(max_paths=42, max_constraint_size=99)
    engine = resource_limits_from_analysis_limits(profile)
    assert engine.max_paths == 42
    assert engine.max_constraints == 99
    assert engine.max_memory_mb == profile.max_memory_mb


def test_analysis_limits_round_trip_preserves_profile_only_fields() -> None:
    profile = AnalysisLimits(max_string_length=2048, max_list_length=64)
    engine = resource_limits_from_analysis_limits(profile)
    restored = analysis_limits_from_resource_limits(
        engine,
        max_string_length=profile.max_string_length,
        max_list_length=profile.max_list_length,
    )
    assert restored.max_paths == profile.max_paths
    assert restored.max_string_length == 2048
    assert restored.max_list_length == 64


def test_resource_limits_from_execution_config_uses_engine_defaults_for_extras() -> None:
    config = ExecutionConfig(max_paths=7, max_depth=8, max_iterations=9, timeout_seconds=1.5)
    limits = resource_limits_from_execution_config(config)
    assert limits.max_paths == 7
    assert limits.max_depth == 8
    assert limits.max_iterations == 9
    assert limits.timeout_seconds == 1.5
    assert limits.max_memory_mb == ResourceLimits().max_memory_mb
    assert limits.max_constraints == ResourceLimits().max_constraints


def test_pysymex_config_engine_resource_limits() -> None:
    cfg = PysymexConfig()
    cfg.limits.max_paths = 321
    assert cfg.engine_resource_limits().max_paths == 321


def test_analysis_limits_to_resource_limits_method() -> None:
    profile = AnalysisLimits(max_depth=17)
    assert profile.to_resource_limits().max_depth == 17
