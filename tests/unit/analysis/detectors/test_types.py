import z3

from pysymex._internal.analysis.detectors.detector.counterexample import CounterexampleExtractor
from pysymex._internal.analysis.detectors.detector.types import Issue, Severity
from pysymex._internal.core.outcome import IssueKind


class TestIssueKind:
    """Test suite for pysymex._internal.analysis.detectors.detector.types.IssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueKind.TYPE_ERROR.name == "TYPE_ERROR"


class TestSeverity:
    """Test suite for pysymex._internal.analysis.detectors.detector.types.Severity."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Severity.CRITICAL.name == "CRITICAL"


class TestIssue:
    """Test suite for pysymex._internal.analysis.detectors.detector.types.Issue."""

    def test_is_suppressed(self) -> None:
        """Test is_suppressed behavior."""
        issue = Issue(
            kind=IssueKind.UNKNOWN, severity=Severity.HIGH, file="f.py", line=10, message="msg"
        )
        assert issue.is_suppressed() is False
        suppressed = Issue(
            kind=IssueKind.UNKNOWN,
            severity=Severity.HIGH,
            file="f.py",
            line=10,
            message="msg",
            suppression_reason="reason",
        )
        assert suppressed.is_suppressed() is True

    def test_format(self) -> None:
        """Test format behavior."""
        issue = Issue(
            kind=IssueKind.UNKNOWN, severity=Severity.HIGH, file="f.py", line=10, message="msg"
        )
        fmt = issue.format()
        assert "[high] unknown" in fmt
        assert "f.py:10" in fmt
        assert "msg" in fmt

    def test_counterexample_prefers_active_string_slot(self) -> None:
        """Scenario: union value model has inactive bool slot; expected string counterexample."""
        query_str = z3.String("query_str")
        query_bool = z3.Bool("query_bool")
        query_is_str = z3.Bool("query_is_str")
        query_is_bool = z3.Bool("query_is_bool")
        solver = z3.Solver()
        solver.add(query_str == "admin", query_bool == z3.BoolVal(False))
        solver.add(query_is_str == z3.BoolVal(True), query_is_bool == z3.BoolVal(False))
        assert solver.check() == z3.sat

        counterexample = CounterexampleExtractor(solver.model(), []).extract()

        assert counterexample["query"] == "admin"

    def test_counterexample_derived_lengths_are_bounded_for_large_arithmetic_expr(
        self,
    ) -> None:
        """Counterexample extraction must not recursively walk huge arithmetic trees."""
        value = z3.Int("counterexample_deep_x")
        expression = value
        for _ in range(512):
            expression = expression + 1

        solver = z3.Solver()
        solver.add(value == 1)
        assert solver.check() == z3.sat

        counterexample = CounterexampleExtractor(
            solver.model(),
            [expression > 0],
        ).extract()

        assert counterexample["counterexample_deep_x"] == 1
