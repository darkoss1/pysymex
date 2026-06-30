"""Tests for canonical config defaults and environment parsing."""

from __future__ import annotations

from pysymex._internal.config.defaults import (
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_TRACE_COMPRESSION_LEVEL,
    DEFAULT_TRACE_OUTPUT_DIR,
    SCAN_OUTPUT_FORMAT_CHOICES,
    VERSION,
)
from pysymex._internal.config.environment import (
    TraceEnvironment,
    async_scanner_process_pool_enabled,
    false_positive_filter_enabled,
    read_trace_environment,
    scanner_issue_dedup_enabled,
)
from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
from pysymex._internal.limits.models import ResourceLimits


def test_public_config_exports_canonical_defaults() -> None:
    assert VERSION == "0.1.1a2"
    assert DEFAULT_SCAN_MAX_PATHS is None
    assert DEFAULT_TRACE_OUTPUT_DIR == ".pysymex/traces"
    assert SCAN_OUTPUT_FORMAT_CHOICES == (
        "text",
        "json",
        "sarif",
        "rich",
        "html",
        "markdown",
    )


def test_runtime_limit_defaults_are_automatic_unless_explicit() -> None:
    resource_limits = ResourceLimits()
    verified_config = ExecutionVerificationConfig()

    assert resource_limits.max_paths is None
    assert resource_limits.max_depth is None
    assert resource_limits.max_constraints is None
    assert verified_config.max_iterations is None
    assert verified_config.timeout_seconds is None


def test_read_trace_environment_uses_canonical_parser() -> None:
    trace_env = read_trace_environment({"PY_SYMEX_TRACE": "yes", "PY_SYMEX_TRACE_COMPRESSION": "9"})

    assert trace_env == TraceEnvironment(enabled=True, compression_level=9)


def test_read_trace_environment_preserves_invalid_compression_fallback() -> None:
    trace_env = read_trace_environment(
        {"PY_SYMEX_TRACE": "0", "PY_SYMEX_TRACE_COMPRESSION": "invalid"}
    )

    assert trace_env.enabled is False
    assert trace_env.compression_level == DEFAULT_TRACE_COMPRESSION_LEVEL


def test_scanner_env_helpers_preserve_disable_flags() -> None:
    assert scanner_issue_dedup_enabled({"PYSYMEX_DISABLE_ISSUE_DEDUP": "true"}) is False
    assert false_positive_filter_enabled({"PYSYMEX_DISABLE_FP_FILTER": "1"}) is False
    assert async_scanner_process_pool_enabled({"PYSYMEX_ASYNC_USE_PROCESS_POOL": "off"}) is False
