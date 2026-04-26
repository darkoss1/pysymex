from pysymex.analysis.detectors.types import TypeEnvironment, DetectionContext
from pysymex.analysis.detectors.base import IssueKind
from unittest.mock import Mock
from pysymex.analysis.detectors.types import (
    IssueKind,
    Severity,
    Issue,
    DetectionContext,
    StaticDetector,
)
from pysymex.analysis.type_inference import PyType, TypeKind, TypeEnvironment


class DummyStaticDetector(StaticDetector):
    def issue_kind(self) -> IssueKind:
        return IssueKind.UNKNOWN

    def check(self, ctx: DetectionContext) -> Issue | None:
        return self.create_issue(ctx, "test msg")


class TestIssueKind:
    """Test suite for pysymex.analysis.detectors.types.IssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueKind.TYPE_ERROR.name == "TYPE_ERROR"


class TestSeverity:
    """Test suite for pysymex.analysis.detectors.types.Severity."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Severity.CRITICAL.name == "CRITICAL"


class TestIssue:
    """Test suite for pysymex.analysis.detectors.types.Issue."""

    def test_is_suppressed(self) -> None:
        """Test is_suppressed behavior."""
        issue = Issue(IssueKind.UNKNOWN, Severity.HIGH, "f.py", 10, "msg")
        assert issue.is_suppressed() is False
        suppressed = Issue(
            IssueKind.UNKNOWN, Severity.HIGH, "f.py", 10, "msg", suppression_reason="reason"
        )
        assert suppressed.is_suppressed() is True

    def test_format(self) -> None:
        """Test format behavior."""
        issue = Issue(IssueKind.UNKNOWN, Severity.HIGH, "f.py", 10, "msg")
        fmt = issue.format()
        assert "[high] unknown" in fmt
        assert "f.py:10" in fmt
        assert "msg" in fmt


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


class TestStaticDetector:
    """Test suite for pysymex.analysis.detectors.types.StaticDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        d = DummyStaticDetector()
        assert d.issue_kind().name == "UNKNOWN"

    def test_check(self) -> None:
        """Test check behavior."""
        d = DummyStaticDetector()
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, TypeEnvironment())
        issue = d.check(ctx)
        assert issue is not None
        assert issue.message == "test msg"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = DummyStaticDetector()
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, TypeEnvironment())
        assert d.should_check(ctx) is True

    def test_get_severity(self) -> None:
        """Test get_severity behavior."""
        d = DummyStaticDetector()
        assert d.get_severity(0.99) == Severity.ERROR
        assert d.get_severity(0.8) == Severity.WARNING
        assert d.get_severity(0.6) == Severity.INFO
        assert d.get_severity(0.1) == Severity.HINT

    def test_create_issue(self) -> None:
        """Test create_issue behavior."""
        d = DummyStaticDetector()
        ctx = DetectionContext(Mock(), [], 0, Mock(), 10, TypeEnvironment(), file_path="t.py")
        issue = d.create_issue(ctx, "test", 0.9)
        assert issue.severity == Severity.WARNING
        assert issue.file == "t.py"

    def test_suppress_issue(self) -> None:
        """Test suppress_issue behavior."""
        d = DummyStaticDetector()
        issue = Issue(IssueKind.UNKNOWN, Severity.HIGH, "f.py", 10, "msg")
        sup = d.suppress_issue(issue, "reason")
        assert sup.suppression_reason == "reason"
