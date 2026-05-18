"""Tests for model side-effect issue conversion."""

from __future__ import annotations

import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.execution.model_effects import issues_from_model_side_effects


def test_raised_exception_side_effect_maps_to_declared_issue_kind() -> None:
    """Raised exception side effects become issues with the declared kind."""
    issues = issues_from_model_side_effects(
        {
            "raised_exception": {
                "issue_kind": "ATTRIBUTE_ERROR",
                "exception_type": "AttributeError",
                "message": "missing attribute",
                "source": "builtins.getattr",
            }
        },
        pc=12,
    )
    assert issues[0].kind == IssueKind.ATTRIBUTE_ERROR


def test_critical_sink_event_side_effect_maps_to_runtime_error() -> None:
    """Critical dynamic-code sink side effects become runtime issues."""
    issues = issues_from_model_side_effects(
        {
            "sink_event": {
                "sink_type": "eval",
                "severity": "critical",
                "source": "builtins.eval",
            }
        },
        pc=7,
    )
    assert issues[0].kind == IssueKind.RUNTIME_ERROR


def test_info_sink_event_side_effect_does_not_emit_issue() -> None:
    """Informational dynamic-code sink side effects do not emit issues."""
    issues = issues_from_model_side_effects(
        {
            "sink_event": {
                "sink_type": "compile",
                "severity": "info",
                "source": "builtins.compile",
            }
        },
        pc=3,
    )
    assert issues == []


def test_potential_exception_emits_issue_when_condition_feasible() -> None:
    """Potential exception side effects are checked against path constraints."""
    x = z3.Int("potential_x")

    issues = issues_from_model_side_effects(
        {
            "potential_exception": {
                "type": "ValueError",
                "message": "missing",
                "condition": x != 1,
            }
        },
        pc=4,
        path_constraints=[x > 1],
        is_sat=_z3_is_sat,
    )

    assert issues[0].kind == IssueKind.VALUE_ERROR


def test_potential_exception_is_suppressed_when_condition_infeasible() -> None:
    """Potential exception side effects do not report infeasible paths."""
    x = z3.Int("potential_x")

    issues = issues_from_model_side_effects(
        {
            "potential_exception": {
                "type": "ValueError",
                "message": "missing",
                "condition": x != 1,
            }
        },
        pc=4,
        path_constraints=[x == 1],
        is_sat=_z3_is_sat,
    )

    assert issues == []


def _z3_is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat
