# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Tests for tracing analyzer constraint-content pipeline filters."""

from __future__ import annotations

from pysymex.tracing.analyzer.pipeline import build_pipeline
from tests.unit.tracing.analyzer.pipeline_args import make_pipeline_args


class TestAnyConstraint:
    """Test the _any_constraint inner filter function."""

    def test_any_constraint_in_constraint_added(self) -> None:
        """_any_constraint finds needle in constraint_added.smtlib."""
        pipeline = build_pipeline(make_pipeline_args(constraint_contains="bvadd"))
        event = {"constraint_added": {"smtlib": "(bvadd x y)", "causality": ""}}
        assert pipeline.matches(event)

    def test_any_constraint_in_path_constraints(self) -> None:
        """_any_constraint finds needle in path_constraints[*].smtlib."""
        pipeline = build_pipeline(make_pipeline_args(constraint_contains="needle_expr"))
        event = {
            "path_constraints": [
                {"smtlib": "(= x needle_expr)", "causality": ""},
            ]
        }
        assert pipeline.matches(event)

    def test_any_constraint_in_detector_query_excerpt(self) -> None:
        """_any_constraint finds needle in detector_query constraint excerpts."""
        pipeline = build_pipeline(make_pipeline_args(constraint_contains="detector_probe"))
        event = {
            "constraint_excerpt": [
                {"smtlib": "(= detector_probe 1)", "causality": ""},
            ]
        }

        assert pipeline.matches(event)

    def test_any_constraint_in_path_feasibility_excerpt(self) -> None:
        """_any_constraint finds needle in path_feasibility query excerpts."""
        pipeline = build_pipeline(make_pipeline_args(constraint_contains="path_probe"))
        event = {
            "query_constraint_excerpt": [
                {"smtlib": "(= path_probe 1)", "causality": ""},
            ]
        }

        assert pipeline.matches(event)

    def test_any_constraint_not_found(self) -> None:
        """_any_constraint returns False when needle is absent everywhere."""
        pipeline = build_pipeline(make_pipeline_args(constraint_contains="ABSENT"))
        event = {"constraint_added": {"smtlib": "(= x 1)", "causality": ""}}
        assert not pipeline.matches(event)
