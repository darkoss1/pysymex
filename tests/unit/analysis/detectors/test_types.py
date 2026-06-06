from unittest.mock import Mock

import z3

from pysymex.analysis.detectors.types import DetectionContext, IssueKind
from pysymex.analysis.detectors.detector.types import CounterexampleExtractor, Issue, Severity
from pysymex.analysis.static.patterns import (
    FunctionPatternInfo,
    PatternMatcher,
    PatternKind,
    PatternMatch,
)
from pysymex.analysis.static.types import PyType, TypeKind, TypeEnvironment


class TestIssueKind:
    """Test suite for pysymex.analysis.detectors.detector.types.IssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueKind.TYPE_ERROR.name == "TYPE_ERROR"


class TestSeverity:
    """Test suite for pysymex.analysis.detectors.detector.types.Severity."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Severity.CRITICAL.name == "CRITICAL"


class TestIssue:
    """Test suite for pysymex.analysis.detectors.types.Issue."""

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


class TestDetectionContext:
    """Test suite for pysymex.analysis.detectors.types.DetectionContext."""

    def test_get_type(self) -> None:
        """Test get_type behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.int_())
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, env)
        assert ctx.get_type("x").kind == TypeKind.INT

    def test_is_definitely_type(self) -> None:
        """Test is_definitely_type behavior."""
        env = TypeEnvironment()
        env.set_type("x", PyType.int_())
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, env)
        assert ctx.is_definitely_type("x", TypeKind.INT) is True
        assert ctx.is_definitely_type("x", TypeKind.STR) is False

    def test_can_pattern_suppress(self) -> None:
        """Test can_pattern_suppress behavior."""
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, TypeEnvironment())
        assert ctx.can_pattern_suppress("Any") is False

    def test_is_in_try_block(self) -> None:
        """Test is_in_try_block behavior."""
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, TypeEnvironment())
        assert ctx.is_in_try_block("Exception") is False

    def test_is_in_try_block_uses_pattern_result_snapshot(self) -> None:
        """Scenario: matcher cache cleared after analysis; expected snapshot still applies."""
        matcher = PatternMatcher()
        match = PatternMatch(
            PatternKind.TRY_EXCEPT_PATTERN,
            0.9,
            10,
            20,
            variables={"caught_exceptions": {"ValueError"}},
        )
        pattern_info = FunctionPatternInfo(patterns=[match], matcher=matcher)
        matcher.clear_cache()
        ctx = DetectionContext(
            Mock(),
            [],
            15,
            Mock(),
            10,
            TypeEnvironment(),
            pattern_info=pattern_info,
        )

        assert ctx.is_in_try_block("ValueError") is True
