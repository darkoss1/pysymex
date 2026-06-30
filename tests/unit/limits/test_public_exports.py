"""Tests for core host-limit exports and limits package ownership."""

from __future__ import annotations

import importlib

import pysymex

LIMIT_EXPORT_OWNERS: dict[str, tuple[str, str]] = {
    "AnalysisTimeoutError": ("pysymex._internal.limits.models", "AnalysisTimeoutError"),
    "LimitExceeded": ("pysymex._internal.limits.models", "LimitExceeded"),
    "ResourceLimits": ("pysymex._internal.limits.models", "ResourceLimits"),
    "ResourceSnapshot": ("pysymex._internal.limits.models", "ResourceSnapshot"),
    "ResourceTracker": ("pysymex._internal.limits.tracker", "ResourceTracker"),
    "ResourceType": ("pysymex._internal.limits.models", "ResourceType"),
    "TimeoutError": ("pysymex._internal.limits.models", "TimeoutError"),
}


def test_core_does_not_reexport_limit_types() -> None:
    """Limit types remain at their implementation owners."""
    for name, (module_path, attribute_name) in LIMIT_EXPORT_OWNERS.items():
        module = importlib.import_module(module_path)
        assert getattr(module, attribute_name) is not None
        assert not hasattr(pysymex, name)


def test_limits_package_has_no_root_public_facade() -> None:
    """The limits package root must not own duplicate public API exports."""
    limits_package = importlib.import_module("pysymex._internal.limits")
    for name in LIMIT_EXPORT_OWNERS:
        assert name not in vars(limits_package)
        assert not hasattr(limits_package, name)
