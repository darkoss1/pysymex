"""Tests for execution detector suppression package ownership."""

from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.detectors.suppression.names import exception_name_for_issue


def _instr(opname: str) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname)


def test_exception_name_for_issue_maps_none_subscript_to_type_error() -> None:
    issue = Issue(kind=IssueKind.NULL_DEREFERENCE, message="none subscript", pc=0)

    assert exception_name_for_issue(issue, _instr("BINARY_SUBSCR")) == "TypeError"


def test_exception_name_for_issue_extracts_unhandled_exception_name() -> None:
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Path raises unhandled exception: CustomError",
        pc=0,
    )

    assert exception_name_for_issue(issue, _instr("CALL")) == "CustomError"


def test_exception_name_for_issue_extracts_unhandled_name_before_detail() -> None:
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Path raises unhandled exception: ExceptionGroup: SymbolicString(name='mixed')",
        pc=0,
    )

    assert exception_name_for_issue(issue, _instr("RAISE_VARARGS")) == "ExceptionGroup"
