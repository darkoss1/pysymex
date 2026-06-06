"""Hundred-case symbolic-execution corpus for basic engine behavior."""

from __future__ import annotations

import pytest

from pysymex.analysis.detectors import IssueKind
from tests.unit.repro.hundred_case_corpus_cases import CASES, CorpusCase
from tests.unit.repro.hundred_case_corpus_runner import build_executor, compile_case


def test_hundred_case_corpus_has_exactly_100_cases() -> None:
    assert len(CASES) == 100
    assert sum(1 for case in CASES if case.expects_clean_run) == 50
    assert sum(1 for case in CASES if not case.expects_clean_run) == 50


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_symbolic_executor_hundred_case_basic_corpus(case: CorpusCase) -> None:
    function = compile_case(case)
    result = build_executor().execute_function(function, symbolic_args=dict(case.symbolic_args))
    actual_issue_kinds = {issue.kind for issue in result.issues}

    assert result.paths_explored >= 1
    assert IssueKind.RUNTIME_ERROR not in actual_issue_kinds
    assert IssueKind.UNKNOWN not in actual_issue_kinds

    if case.expects_clean_run:
        assert actual_issue_kinds == set()
    else:
        assert case.expected_issue_kinds <= actual_issue_kinds
