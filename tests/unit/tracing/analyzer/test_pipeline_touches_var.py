# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Tests for tracing analyzer variable-touch pipeline filters."""

from __future__ import annotations

from pysymex.tracing.analyzer.pipeline import build_pipeline
from tests.unit.tracing.analyzer.pipeline_args import make_pipeline_args


class TestTouchesVar:
    """Test the _touches_var inner filter function."""

    def test_touches_var_in_stack(self) -> None:
        """_touches_var finds needle in stack list."""
        pipeline = build_pipeline(make_pipeline_args(touches_var="my_var"))
        event = {"stack": ["my_var_value", "other"]}
        assert pipeline.matches(event)

    def test_touches_var_in_local_vars(self) -> None:
        """_touches_var finds needle in local_vars mapping."""
        pipeline = build_pipeline(make_pipeline_args(touches_var="target"))
        event = {"local_vars": {"target": "42"}}
        assert pipeline.matches(event)

    def test_touches_var_not_found(self) -> None:
        """_touches_var returns False when needle is absent."""
        pipeline = build_pipeline(make_pipeline_args(touches_var="absent_var"))
        event = {"stack": ["x", "y"], "local_vars": {"a": "1"}}
        assert not pipeline.matches(event)
