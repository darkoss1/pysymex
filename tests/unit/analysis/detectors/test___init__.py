"""Tests for pysymex/_internal/analysis/detectors/__init__.py."""

from pysymex._internal.analysis.detectors.defaults import default_registry


def test_default_registry_excludes_runtime_unreachable_detector() -> None:
    """Default detector registry should not include runtime unreachable-code checks."""
    available = default_registry.list_available()
    assert "unreachable-code" not in available


def test_default_registry_excludes_logical_contradiction_detector() -> None:
    """Logical contradiction detector stays opt-in until precision is improved."""
    available = default_registry.list_available()
    assert "logical-contradiction" not in available
