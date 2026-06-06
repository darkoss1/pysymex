"""Tests for detector issue-evidence helpers."""

from __future__ import annotations

import z3

from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex.analysis.detectors.detector.types import IssueKind
from pysymex.analysis.detectors.feasibility import FeasibilityModelResult


def test_issue_from_feasibility_evidence_suppresses_no_sat_evidence() -> None:
    issue = issue_from_feasibility_evidence(
        result=FeasibilityModelResult.no_sat_evidence("unit"),
        kind=IssueKind.KEY_ERROR,
        message="Possible KeyError",
        constraints=[],
        pc=7,
    )

    assert issue is None


def test_issue_from_feasibility_evidence_reports_inconclusive_without_model() -> None:
    issue = issue_from_feasibility_evidence(
        result=FeasibilityModelResult.inconclusive("unit"),
        kind=IssueKind.KEY_ERROR,
        message="Possible KeyError",
        constraints=[],
        pc=7,
    )

    assert issue is not None
    assert "Path feasibility inconclusive" in issue.message
    assert issue.model is None
    assert issue.confidence == 0.5
    assert issue.likelihood == 0.5


def test_issue_from_feasibility_evidence_suppresses_locally_false_inconclusive_query() -> None:
    guard = z3.Bool("guarded_missing_key")

    issue = issue_from_feasibility_evidence(
        result=FeasibilityModelResult.no_sat_evidence("prefix_unknown"),
        kind=IssueKind.KEY_ERROR,
        message="Possible KeyError",
        constraints=[guard, z3.Not(guard)],
        pc=7,
        path_is_inconclusive=True,
    )

    assert issue is None


def test_constraints_extend_inconclusive_path_requires_valid_matching_prefix() -> None:
    first = z3.Bool("first")
    second = z3.Bool("second")

    assert constraints_extend_inconclusive_path(
        path_constraints=[first],
        constraints=[first, second],
        last_inconclusive_feasibility_len=1,
    )
    assert not constraints_extend_inconclusive_path(
        path_constraints=[first],
        constraints=[first, second],
        last_inconclusive_feasibility_len=2,
    )
    assert not constraints_extend_inconclusive_path(
        path_constraints=[first],
        constraints=[second],
        last_inconclusive_feasibility_len=1,
    )
