from types import SimpleNamespace

from pysymex.analysis.detectors import IssueKind
from pysymex.api import analyze


def test_dict_merge():
    """Test merging of dictionary values."""

    def target(x: int):
        d = {"val": 0}
        if x > 10:
            d["val"] = 100
        else:
            d["val"] = 200

        # Merge point
        # d["val"] should be symbolic: If(x>10, 100, 200)

        if d["val"] == 100:
            if x <= 10:
                10 // 0  # Impossible  # type: ignore[reportUnusedExpression]

        if d["val"] == 200:
            if x > 10:
                10 // 0  # Impossible  # type: ignore[reportUnusedExpression]

    result = analyze(target, {"x": "int"})
    # Only check for real bug issues; UNREACHABLE_CODE FPs are a known limitation
    # with dict/SimpleNamespace attribute merging.
    bug_issues = [i for i in result.issues if i.kind != IssueKind.UNREACHABLE_CODE]
    assert not bug_issues


def test_object_merge():
    """Test merging of object attributes (SimpleNamespace)."""

    def target(x: int):
        p = SimpleNamespace(val=0)
        if x > 10:
            p.val = 100
        else:
            p.val = 200

        if p.val == 100:
            if x <= 10:
                10 // 0  # Impossible  # type: ignore[reportUnusedExpression]

    result = analyze(target, {"x": "int"})
    bug_issues = [i for i in result.issues if i.kind != IssueKind.UNREACHABLE_CODE]
    assert not bug_issues


def test_path_explosion_simplest():
    """Simplified path explosion test."""

    def target(n: int):
        obj = SimpleNamespace(v=0)
        if n > 0:
            obj.v = 1
        else:
            obj.v = 0  # Explicit else branch for proper merge

        # If n > 0, obj.v must be 1.
        if obj.v == 1:
            if n <= 0:
                10 // 0  # Impossible  # type: ignore[reportUnusedExpression]

    result = analyze(target, {"n": "int"})
    bug_issues = [i for i in result.issues if i.kind != IssueKind.UNREACHABLE_CODE]
    assert not bug_issues
