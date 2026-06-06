"""Tests for canonical config defaults and environment parsing."""

from __future__ import annotations

import pysymex.config as config
from pysymex.execution.executors.verified.types import VerifiedExecutionConfig
from pysymex.resources.mapping import resource_limits_from_analysis_limits


def test_public_config_exports_canonical_defaults() -> None:
    assert config.VERSION == "0.1.1a1"
    assert config.DEFAULT_SCAN_MAX_PATHS == 5000
    assert config.DEFAULT_TRACE_OUTPUT_DIR == ".pysymex/traces"
    assert config.SCAN_OUTPUT_FORMAT_CHOICES == (
        "text",
        "json",
        "sarif",
        "rich",
        "html",
        "markdown",
    )


def test_analysis_limit_defaults_share_config_owner() -> None:
    limits = config.AnalysisLimits()
    resource_limits = resource_limits_from_analysis_limits(limits)
    verified_config = VerifiedExecutionConfig()

    assert resource_limits.max_paths == limits.max_paths == config.DEFAULT_LIMIT_MAX_PATHS
    assert resource_limits.max_depth == limits.max_depth == config.DEFAULT_LIMIT_MAX_DEPTH
    assert resource_limits.max_constraints == limits.max_constraint_size
    assert verified_config.max_iterations == limits.max_iterations
    assert verified_config.timeout_seconds == limits.timeout_seconds


def test_read_trace_environment_uses_canonical_parser() -> None:
    trace_env = config.read_trace_environment(
        {"PY_SYMEX_TRACE": "yes", "PY_SYMEX_TRACE_COMPRESSION": "9"}
    )

    assert trace_env == config.TraceEnvironment(enabled=True, compression_level=9)


def test_read_trace_environment_preserves_invalid_compression_fallback() -> None:
    trace_env = config.read_trace_environment(
        {"PY_SYMEX_TRACE": "0", "PY_SYMEX_TRACE_COMPRESSION": "invalid"}
    )

    assert trace_env.enabled is False
    assert trace_env.compression_level == config.DEFAULT_TRACE_COMPRESSION_LEVEL


def test_scanner_env_helpers_preserve_disable_flags() -> None:
    assert config.scanner_issue_dedup_enabled({"PYSYMEX_DISABLE_ISSUE_DEDUP": "true"}) is False
    assert config.false_positive_filter_enabled({"PYSYMEX_DISABLE_FP_FILTER": "1"}) is False
    assert (
        config.async_scanner_process_pool_enabled({"PYSYMEX_ASYNC_USE_PROCESS_POOL": "off"})
        is False
    )
