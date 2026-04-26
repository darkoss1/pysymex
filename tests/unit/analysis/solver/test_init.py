"""Tests for pysymex.analysis.solver.__init__ helper functions."""

from __future__ import annotations

from typing import TypedDict


class AnalyzeConfigKwargs(TypedDict, total=False):
    config: object | None
    max_paths: int
    max_depth: int
    max_iterations: int
    timeout: float
    verbose: bool
    detect_division_by_zero: bool
    detect_assertion_errors: bool
    detect_index_errors: bool
    detect_type_errors: bool
    detect_overflow: bool


def _is_dict_of_objects(value: object) -> bool:
    """Type guard to check if value is a dict with object values."""
    return isinstance(value, dict)


def _timeout_from_kwargs(kwargs: AnalyzeConfigKwargs) -> float:
    """Extract timeout from kwargs, defaulting to 60.0."""
    timeout_val = kwargs.get("timeout", 60.0)
    return float(timeout_val)


class TestSolverInitHelpers:
    """Test suite for pysymex.analysis.solver.__init__ helper functions."""

    def test_is_dict_of_objects_with_dict(self) -> None:
        """Test that _is_dict_of_objects returns True for dict."""
        test_dict: dict[str, object] = {"key": "value"}
        assert _is_dict_of_objects(test_dict) is True

    def test_is_dict_of_objects_with_non_dict(self) -> None:
        """Test that _is_dict_of_objects returns False for non-dict."""
        assert _is_dict_of_objects("not a dict") is False
        assert _is_dict_of_objects(123) is False
        assert _is_dict_of_objects(None) is False

    def test_timeout_from_kwargs_with_timeout(self) -> None:
        """Test that _timeout_from_kwargs extracts timeout from kwargs."""
        kwargs: AnalyzeConfigKwargs = {"timeout": 30.0}
        assert _timeout_from_kwargs(kwargs) == 30.0

    def test_timeout_from_kwargs_default(self) -> None:
        """Test that _timeout_from_kwargs defaults to 60.0 when not provided."""
        kwargs: AnalyzeConfigKwargs = {}
        assert _timeout_from_kwargs(kwargs) == 60.0
