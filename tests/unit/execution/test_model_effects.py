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


def test_raised_exception_side_effect_keeps_path_constraints() -> None:
    """Raised exception side effects carry the active path constraints."""
    x = z3.Int("raised_exception_path_x")
    constraints = [x == 1]

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
        path_constraints=constraints,
        path_may_be_feasible=_z3_is_sat,
    )

    assert len(issues) == 1
    assert len(issues[0].constraints) == 1
    assert z3.eq(issues[0].constraints[0], constraints[0])


def test_raised_exception_side_effect_suppresses_infeasible_path() -> None:
    """Raised exception side effects do not report infeasible active paths."""
    x = z3.Int("raised_exception_infeasible_x")

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
        path_constraints=[x == 1, x != 1],
        path_may_be_feasible=_z3_is_sat,
    )

    assert issues == []


def test_raised_exception_side_effect_reports_inconclusive_prefix_as_possible_issue() -> None:
    """Model-raised exceptions under inconclusive path prefixes are possible issues."""
    x = z3.Int("raised_exception_inconclusive_x")
    constraints = [x > 0]

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
        path_constraints=constraints,
        path_may_be_feasible=lambda _constraints: False,
        last_inconclusive_feasibility_len=1,
    )

    assert len(issues) == 1
    assert issues[0].kind == IssueKind.ATTRIBUTE_ERROR
    assert "Path feasibility inconclusive" in issues[0].message
    assert issues[0].model is None
    assert issues[0].confidence == 0.5
    assert issues[0].detector_name == "model-side-effect"


def test_raised_exception_side_effect_does_not_override_literal_false_path() -> None:
    """Inconclusive-prefix reporting must not override locally false constraints."""
    x = z3.Int("raised_exception_literal_false_x")

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
        path_constraints=[x > 0, z3.BoolVal(False)],
        path_may_be_feasible=lambda _constraints: False,
        last_inconclusive_feasibility_len=1,
    )

    assert issues == []


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
    assert issues[0].detector_name == "model-side-effect"


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
        path_may_be_feasible=_z3_is_sat,
    )

    assert issues[0].kind == IssueKind.VALUE_ERROR


def test_potential_exception_sequence_emits_each_feasible_issue() -> None:
    """Models can report multiple independently gated potential exceptions."""
    x = z3.Int("potential_x")

    issues = issues_from_model_side_effects(
        {
            "potential_exceptions": [
                {
                    "type": "ValueError",
                    "message": "domain",
                    "condition": x <= 0,
                },
                {
                    "type": "ZeroDivisionError",
                    "message": "base one",
                    "condition": x == 1,
                },
            ]
        },
        pc=4,
        path_constraints=[x >= 0],
        path_may_be_feasible=_z3_is_sat,
    )

    assert [issue.kind for issue in issues] == [
        IssueKind.VALUE_ERROR,
        IssueKind.DIVISION_BY_ZERO,
    ]


def test_potential_overflow_exception_maps_to_overflow_issue() -> None:
    """Potential OverflowError side effects should use the public OVERFLOW issue kind."""
    x = z3.Int("overflow_x")

    issues = issues_from_model_side_effects(
        {
            "potential_exception": {
                "type": "OverflowError",
                "message": "math range error",
                "condition": x >= 710,
            }
        },
        pc=4,
        path_constraints=[x == 710],
        path_may_be_feasible=_z3_is_sat,
    )

    assert issues[0].kind == IssueKind.OVERFLOW


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
        path_may_be_feasible=_z3_is_sat,
    )

    assert issues == []


def _z3_is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat
