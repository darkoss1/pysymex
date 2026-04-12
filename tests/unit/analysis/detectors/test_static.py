import pytest
import dis
from unittest.mock import Mock, patch
from pysymex.analysis.detectors.static import (
    DetectorRegistry, StaticAnalyzer, StaticDivisionByZeroDetector,
    StaticKeyErrorDetector, StaticIndexErrorDetector, StaticTypeErrorDetector,
    StaticAttributeErrorDetector, StaticAssertionErrorDetector, DeadCodeDetector
)
from pysymex.analysis.detectors.types import IssueKind, DetectionContext
from pysymex.analysis.type_inference import PyType, TypeEnvironment, TypeKind

class MockInstr:
    def __init__(self, opname: str, argval: object = None, argrepr: str = "", offset: int = 10, starts_line: int | None = 10) -> None:
        self.opname = opname
        self.argval = argval
        self.argrepr = argrepr
        self.offset = offset
        self.starts_line = starts_line
        self.positions = Mock(lineno=starts_line) if starts_line else None

def create_mock_ctx(instr: MockInstr, env: TypeEnvironment | None = None) -> DetectionContext:
    if env is None:
        env = TypeEnvironment()
    return DetectionContext(
        code=Mock(co_name="f", co_firstlineno=1),
        instructions=[instr],
        pc=instr.offset,
        instruction=instr, # type: ignore[arg-type]
        line=instr.starts_line or 1,
        type_env=env,
        file_path="f.py"
    )

class TestDetectorRegistry:
    """Test suite for pysymex.analysis.detectors.static.DetectorRegistry."""
    def test_register(self) -> None:
        """Test register behavior."""
        r = DetectorRegistry()
        d = StaticDivisionByZeroDetector()
        r.register(d)
        assert d in r.detectors

    def test_get_all(self) -> None:
        """Test get_all behavior."""
        r = DetectorRegistry()
        all_d = r.get_all()
        assert len(all_d) > 0
        assert any(isinstance(d, StaticDivisionByZeroDetector) for d in all_d)

class TestStaticAnalyzer:
    """Test suite for pysymex.analysis.detectors.static.StaticAnalyzer."""
    @patch("pysymex.analysis.detectors.static._cached_get_instructions")
    @patch("pysymex.analysis.detectors.static.PatternAnalyzer.analyze_function")
    def test_analyze_function(self, mock_analyze_func, mock_get_instr) -> None:
        """Test analyze_function behavior."""
        analyzer = StaticAnalyzer()
        mock_get_instr.return_value = [
            MockInstr("BINARY_OP", argrepr="/")
        ]
        mock_analyze_func.return_value = Mock()
        code = Mock(co_name="f", co_firstlineno=1)
        issues = analyzer.analyze_function(code) # type: ignore[arg-type]
        assert isinstance(issues, list)

class TestStaticDivisionByZeroDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticDivisionByZeroDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticDivisionByZeroDetector().issue_kind() == IssueKind.DIVISION_BY_ZERO

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticDivisionByZeroDetector()
        ctx = create_mock_ctx(MockInstr("BINARY_OP", argrepr="/"))
        assert d.should_check(ctx) is True
        ctx2 = create_mock_ctx(MockInstr("BINARY_OP", argrepr="+"))
        assert d.should_check(ctx2) is False

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticDivisionByZeroDetector()
        instr1 = MockInstr("LOAD_CONST", argval=0, offset=0)
        instr2 = MockInstr("BINARY_OP", argrepr="/", offset=2)
        env = TypeEnvironment()
        ctx = DetectionContext(Mock(), [instr1, instr2], 2, instr2, 10, env) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert "constant 0" in issue.message

class TestStaticKeyErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticKeyErrorDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticKeyErrorDetector().issue_kind() == IssueKind.KEY_ERROR

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticKeyErrorDetector()
        ctx = create_mock_ctx(MockInstr("BINARY_SUBSCR"))
        assert d.should_check(ctx) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticKeyErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_FAST", argval="d", offset=2)
        instr2 = MockInstr("LOAD_CONST", argval="k", offset=4)
        instr3 = MockInstr("BINARY_SUBSCR", offset=6)
        env = TypeEnvironment()
        env.set_type("d", PyType.dict_())
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.KEY_ERROR

class TestStaticIndexErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticIndexErrorDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticIndexErrorDetector().issue_kind() == IssueKind.INDEX_ERROR

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticIndexErrorDetector()
        ctx = create_mock_ctx(MockInstr("BINARY_SUBSCR"))
        assert d.should_check(ctx) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticIndexErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_FAST", argval="lst", offset=2)
        instr2 = MockInstr("LOAD_CONST", argval=10, offset=4)
        instr3 = MockInstr("BINARY_SUBSCR", offset=6)
        env = TypeEnvironment()
        env.set_type("lst", PyType.list_())
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.INDEX_ERROR

class TestStaticTypeErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticTypeErrorDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticTypeErrorDetector().issue_kind() == IssueKind.TYPE_ERROR

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticTypeErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("BINARY_OP"))) is True
        assert d.should_check(create_mock_ctx(MockInstr("CALL"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticTypeErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_CONST", argval=1, offset=2)
        instr2 = MockInstr("LOAD_CONST", argval="a", offset=4)
        instr3 = MockInstr("BINARY_OP", argrepr="+", offset=6)
        env = TypeEnvironment()
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.TYPE_ERROR

class TestStaticAttributeErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticAttributeErrorDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticAttributeErrorDetector().issue_kind() == IssueKind.ATTRIBUTE_ERROR

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticAttributeErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("LOAD_ATTR"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticAttributeErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_FAST", argval="obj", offset=2)
        instr2 = MockInstr("LOAD_ATTR", argval="missing", offset=4)
        env = TypeEnvironment()
        env.set_type("obj", PyType.none_type())
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2], 4, instr2, 10, env) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.ATTRIBUTE_ERROR

class TestStaticAssertionErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticAssertionErrorDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticAssertionErrorDetector().issue_kind() == IssueKind.ASSERTION_ERROR

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticAssertionErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("LOAD_ASSERTION_ERROR"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticAssertionErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_CONST", argval=False, offset=2)
        instr2 = MockInstr("LOAD_ASSERTION_ERROR", offset=4)
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2], 4, instr2, 10, TypeEnvironment()) # type: ignore[arg-type]
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.ASSERTION_ERROR

class TestDeadCodeDetector:
    """Test suite for pysymex.analysis.detectors.static.DeadCodeDetector."""
    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert DeadCodeDetector().issue_kind() == IssueKind.DEAD_CODE

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = DeadCodeDetector()
        ctx = create_mock_ctx(MockInstr("NOP"))
        assert d.should_check(ctx) is False # no flow_context
        ctx.flow_context = Mock()
        assert d.should_check(ctx) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = DeadCodeDetector()
        ctx = create_mock_ctx(MockInstr("NOP"))
        flow = Mock()
        flow.block = Mock(id=1)
        flow.analyzer.cfg.is_reachable.return_value = False
        ctx.flow_context = flow
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind == IssueKind.DEAD_CODE
