import pytest

from types import SimpleNamespace

from pysymex.api import analyze

from pysymex.analysis.detectors import IssueKind


class Payload:
    def __init__(self):
        self.data = 0


def test_merged_state():
    """
    Verify that division by zero bugs are detected when dividing by a
    symbolic value that could be zero.
    """

    def target(x: int):
        result = 10 // x

    result = analyze(target, {"x": "int"})

    assert result.has_issues()

    assert any(i.kind == IssueKind.DIVISION_BY_ZERO for i in result.issues)


def test_path_explosion_resistance():
    """
    Verify that sequential branches with explicit else work correctly.
    This tests basic branch handling rather than full path explosion merging.
    """

    def target(n: int):
        obj = SimpleNamespace(data=0)

        if n > 5:
            obj.data = 100

        else:
            obj.data = 50

        if obj.data == 100:
            if n <= 5:
                10 // 0

    result = analyze(target, {"n": "int"}, timeout=5.0)

    bug_issues = [i for i in result.issues if i.kind != IssueKind.UNREACHABLE_CODE]

    assert not bug_issues
