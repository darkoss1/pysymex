import pytest
import z3
from unittest.mock import Mock
from pysymex.analysis.detectors.base import (
    IssueKind, Issue, DetectorInfo, Detector, DivisionByZeroDetector,
    AssertionErrorDetector, IndexErrorDetector, KeyErrorDetector,
    TypeErrorDetector, AttributeErrorDetector, OverflowDetector,
    ResourceLeakDetector, ValueErrorDetector, EnhancedIndexErrorDetector,
    NoneDereferenceDetector, EnhancedTypeErrorDetector, FormatStringDetector,
    UnboundVariableDetector, TaintFlowDetector, DetectorRegistry
)

class MockInstr:
    def __init__(self, opname: str, argval: object = None, argrepr: str = "") -> None:
        self.opname = opname
        self.argval = argval
        self.argrepr = argrepr
        self.offset = 10

class DummyDetector(Detector):
    name = "dummy"
    description = "dummy description"
    issue_kind = IssueKind.UNKNOWN
    
    def check(self, state, instruction, _solver_check):
        return None

class TestIssueKind:
    """Test suite for pysymex.analysis.detectors.base.IssueKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueKind.DIVISION_BY_ZERO.name == "DIVISION_BY_ZERO"

class TestIssue:
    """Test suite for pysymex.analysis.detectors.base.Issue."""
    def test_get_counterexample(self) -> None:
        """Test get_counterexample behavior."""
        issue1 = Issue(IssueKind.UNKNOWN, "msg")
        assert issue1.get_counterexample() == {}
        
        # Test dict model
        issue2 = Issue(IssueKind.UNKNOWN, "msg", model={"x": 1}) # type: ignore[arg-type]
        assert issue2.get_counterexample() == {"x": 1}

    def test_format(self) -> None:
        """Test format behavior."""
        issue = Issue(IssueKind.UNKNOWN, "msg", filename="test.py", line_number=10, pc=5)
        fmt = issue.format()
        assert "[UNKNOWN] msg" in fmt
        assert "Location: test.py, line 10" in fmt
        assert "PC: 5" in fmt

    def test_to_dict(self) -> None:
        """Test to_dict behavior."""
        issue = Issue(IssueKind.UNKNOWN, "msg", pc=5)
        d = issue.to_dict()
        assert d["kind"] == "UNKNOWN"
        assert d["message"] == "msg"
        assert d["pc"] == 5

class TestDetectorInfo:
    """Test suite for pysymex.analysis.detectors.base.DetectorInfo."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = DetectorInfo("name", "desc", IssueKind.UNKNOWN)
        assert info.name == "name"

class TestDetector:
    """Test suite for pysymex.analysis.detectors.base.Detector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = DummyDetector()
        assert d.check(Mock(), Mock(), Mock()) is None

    def test_to_info(self) -> None:
        """Test to_info behavior."""
        d = DummyDetector()
        info = d.to_info()
        assert info.name == "dummy"
        assert info.issue_kind == IssueKind.UNKNOWN

    def test_as_fn(self) -> None:
        """Test as_fn behavior."""
        d = DummyDetector()
        fn = d.as_fn()
        assert fn(Mock(), Mock(), Mock()) is None

class TestDivisionByZeroDetector:
    """Test suite for pysymex.analysis.detectors.base.DivisionByZeroDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = DivisionByZeroDetector()
        instr = MockInstr("BINARY_OP", "/", "/")
        state = Mock(stack=[1, 0], path_constraints=[], pc=1)
        # 0 is concrete 0
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.DIVISION_BY_ZERO

class TestAssertionErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.AssertionErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = AssertionErrorDetector()
        instr = MockInstr("RAISE_VARARGS", 1)
        err = Mock()
        err.name = "AssertionError"
        state = Mock(stack=[err], path_constraints=[], pc=1)
        state.peek = Mock(return_value=err)
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.ASSERTION_ERROR

class TestIndexErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.IndexErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = IndexErrorDetector()
        instr = MockInstr("BINARY_SUBSCR")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestKeyErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.KeyErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = KeyErrorDetector()
        instr = MockInstr("BINARY_SUBSCR")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestTypeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.TypeErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = TypeErrorDetector()
        instr = MockInstr("BINARY_OP", "+", "+")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestAttributeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.AttributeErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = AttributeErrorDetector()
        instr = MockInstr("LOAD_ATTR", "attr")
        assert d.check(Mock(), instr, lambda c: True) is None # type: ignore[arg-type]

class TestOverflowDetector:
    """Test suite for pysymex.analysis.detectors.base.OverflowDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = OverflowDetector()
        instr = MockInstr("BINARY_OP", "+", "+")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestResourceLeakDetector:
    """Test suite for pysymex.analysis.detectors.base.ResourceLeakDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = ResourceLeakDetector()
        instr = MockInstr("POP_TOP")
        assert d.check(Mock(), instr, lambda c: True) is None # type: ignore[arg-type]

class TestValueErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.ValueErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = ValueErrorDetector()
        instr = MockInstr("CALL", 1)
        val = Mock(_potential_exception="ValueError")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1, local_vars={"x": val})
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.VALUE_ERROR

class TestEnhancedIndexErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.EnhancedIndexErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = EnhancedIndexErrorDetector()
        instr = MockInstr("BINARY_SUBSCR")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestNoneDereferenceDetector:
    """Test suite for pysymex.analysis.detectors.base.NoneDereferenceDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = NoneDereferenceDetector()
        instr = MockInstr("LOAD_ATTR", "attr")
        state = Mock(stack=[1], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestEnhancedTypeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.EnhancedTypeErrorDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = EnhancedTypeErrorDetector()
        instr = MockInstr("BINARY_SUBSCR")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1) # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestFormatStringDetector:
    """Test suite for pysymex.analysis.detectors.base.FormatStringDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = FormatStringDetector()
        instr = MockInstr("FORMAT_VALUE")
        tracker = Mock()
        tracker.is_tainted.return_value = True
        state = Mock(stack=[1], path_constraints=[], pc=1, taint_tracker=tracker)
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.FORMAT_STRING_INJECTION

class TestUnboundVariableDetector:
    """Test suite for pysymex.analysis.detectors.base.UnboundVariableDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = UnboundVariableDetector()
        instr = MockInstr("LOAD_FAST", "x")
        from pysymex.core.state import UNBOUND
        state = Mock(path_constraints=[], pc=1)
        state.get_local.return_value = UNBOUND
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.UNBOUND_VARIABLE

class TestTaintFlowDetector:
    """Test suite for pysymex.analysis.detectors.base.TaintFlowDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = TaintFlowDetector()
        instr = MockInstr("NOP")
        assert d.check(Mock(taint_tracker=None), instr, lambda c: True) is None # type: ignore[arg-type]

class TestDetectorRegistry:
    """Test suite for pysymex.analysis.detectors.base.DetectorRegistry."""
    def test_register(self) -> None:
        """Test register behavior."""
        r = DetectorRegistry()
        r.register(DummyDetector)
        assert "dummy" in r._detectors

    def test_register_fn(self) -> None:
        """Test register_fn behavior."""
        r = DetectorRegistry()
        def dummy_fn(s: object, i: object, c: object) -> None: pass
        info = DetectorInfo("dfn", "desc", IssueKind.UNKNOWN)
        r.register_fn(dummy_fn, info)
        assert "dfn" in r._fn_detectors

    def test_get(self) -> None:
        """Test get behavior."""
        r = DetectorRegistry()
        assert isinstance(r.get("division-by-zero"), DivisionByZeroDetector)
        assert r.get("unknown") is None

    def test_get_all(self) -> None:
        """Test get_all behavior."""
        r = DetectorRegistry()
        all_d = r.get_all()
        assert len(all_d) > 0
        assert any(isinstance(d, DivisionByZeroDetector) for d in all_d)

    def test_get_all_fns(self) -> None:
        """Test get_all_fns behavior."""
        r = DetectorRegistry()
        fns = r.get_all_fns()
        assert len(fns) > 0

    def test_get_by_kind(self) -> None:
        """Test get_by_kind behavior."""
        r = DetectorRegistry()
        divs = r.get_by_kind(IssueKind.DIVISION_BY_ZERO)
        assert any(isinstance(d, DivisionByZeroDetector) for d in divs)

    def test_list_available(self) -> None:
        """Test list_available behavior."""
        r = DetectorRegistry()
        avail = r.list_available()
        assert "division-by-zero" in avail
