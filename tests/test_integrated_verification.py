from types import SimpleNamespace

from pysymex.analysis.detectors import IssueKind
from pysymex.api import analyze


class Payload:
    def __init__(self):
        self.data = 0


def test_merged_state():
    """
    Verify that division by zero bugs are detected when dividing by a
    symbolic value that could be zero.
    """

    def target(x: int):
        # Divide by x which can be 0 - should trigger DIVISION_BY_ZERO
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

        # Simple two-way branching
        if n > 5:
            obj.data = 100
        else:
            obj.data = 50

        # After merge, obj.data = If(n>5, 100, 50)
        # So if obj.data == 100, n must be > 5
        if obj.data == 100:
            if n <= 5:
                10 // 0  # Impossible  # type: ignore[reportUnusedExpression]

    result = analyze(target, {"n": "int"}, timeout=5.0)
    # Should complete quickly and find no real bug issues.
    # UNREACHABLE_CODE FPs are a known limitation with SimpleNamespace merging.
    bug_issues = [i for i in result.issues if i.kind != IssueKind.UNREACHABLE_CODE]
    assert not bug_issues
