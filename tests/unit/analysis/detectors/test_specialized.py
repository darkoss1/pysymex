import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.detectors.specialized import (
    NullDereferenceDetector, InfiniteLoopDetector, ResourceLeakDetector,
    UseAfterFreeDetector, IntegerOverflowDetector, FormatStringDetector,
    CommandInjectionDetector, PathTraversalDetector, SQLInjectionDetector,
    UnreachableCodeDetector, register_advanced_detectors
)
from pysymex.analysis.detectors.base import IssueKind, DetectorRegistry

class MockInstr:
    def __init__(self, opname: str, arg: int | None = None, argval: object = None, argrepr: str = "") -> None:
        self.opname = opname
        self.arg = arg
        self.argval = argval
        self.argrepr = argrepr

class TestNullDereferenceDetector:
    """Test suite for pysymex.analysis.detectors.specialized.NullDereferenceDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = NullDereferenceDetector()
        instr = MockInstr("LOAD_ATTR", argval="attr")
        state = Mock(stack=[Mock()], pc=1, path_constraints=[])
        
        # Test with a mock that is not None
        assert d.check(state, instr, lambda c: False) is None # type: ignore[arg-type]

class TestInfiniteLoopDetector:
    """Test suite for pysymex.analysis.detectors.specialized.InfiniteLoopDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = InfiniteLoopDetector()
        instr = MockInstr("JUMP_BACKWARD")
        state = Mock(pc=1)
        
        d._max_iterations = 2
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.INFINITE_LOOP

class TestResourceLeakDetector:
    """Test suite for pysymex.analysis.detectors.specialized.ResourceLeakDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = ResourceLeakDetector()
        # Open resource
        instr1 = MockInstr("CALL", arg=0)
        state1 = Mock(stack=[Mock(name="open", qualname="open")])
        d.check(state1, instr1, lambda c: True) # type: ignore[arg-type]
        assert d._open_resources == 1
        
        # Return without closing
        instr2 = MockInstr("RETURN_VALUE")
        issue = d.check(state1, instr2, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.RESOURCE_LEAK

class TestUseAfterFreeDetector:
    """Test suite for pysymex.analysis.detectors.specialized.UseAfterFreeDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = UseAfterFreeDetector()
        obj = Mock(name="file_obj")
        # Call close
        instr1 = MockInstr("CALL", arg=0)
        state1 = Mock(stack=[obj, Mock(qualname="file_obj.close")])
        d.check(state1, instr1, lambda c: True) # type: ignore[arg-type]
        
        # Use
        instr2 = MockInstr("LOAD_METHOD")
        state2 = Mock(stack=[obj], pc=1)
        state2.peek.return_value = obj
        issue = d.check(state2, instr2, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.ATTRIBUTE_ERROR

class TestIntegerOverflowDetector:
    """Test suite for pysymex.analysis.detectors.specialized.IntegerOverflowDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = IntegerOverflowDetector()
        instr = MockInstr("BINARY_OP", argrepr="+")
        state = Mock(stack=[1, 2], path_constraints=[])
        # Returns None because inputs aren't SymbolicValue
        assert d.check(state, instr, lambda c: True) is None # type: ignore[arg-type]

class TestFormatStringDetector:
    """Test suite for pysymex.analysis.detectors.specialized.FormatStringDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = FormatStringDetector()
        instr = MockInstr("FORMAT_VALUE")
        val = Mock(taint_labels={"user_input"})
        state = Mock(stack=[val], pc=1)
        state.peek.return_value = val
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.INVALID_ARGUMENT

class TestCommandInjectionDetector:
    """Test suite for pysymex.analysis.detectors.specialized.CommandInjectionDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = CommandInjectionDetector()
        instr = MockInstr("CALL", arg=1)
        val = Mock(taint_labels={"user_input"})
        state = Mock(stack=[Mock(qualname="os.system"), val], pc=1)
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.INVALID_ARGUMENT

class TestPathTraversalDetector:
    """Test suite for pysymex.analysis.detectors.specialized.PathTraversalDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = PathTraversalDetector()
        instr = MockInstr("CALL", arg=1)
        val = Mock(taint_labels={"user_input"})
        state = Mock(stack=[Mock(qualname="open"), val], pc=1)
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.INVALID_ARGUMENT

class TestSQLInjectionDetector:
    """Test suite for pysymex.analysis.detectors.specialized.SQLInjectionDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = SQLInjectionDetector()
        instr = MockInstr("CALL", arg=1)
        val = Mock(taint_labels={"user_input"})
        state = Mock(stack=[Mock(qualname="db.execute"), val], pc=1)
        issue = d.check(state, instr, lambda c: True) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.INVALID_ARGUMENT

class TestUnreachableCodeDetector:
    """Test suite for pysymex.analysis.detectors.specialized.UnreachableCodeDetector."""
    def test_check(self) -> None:
        """Test check behavior."""
        d = UnreachableCodeDetector()
        instr = MockInstr("NOP")
        state = Mock(path_constraints=["c1"], pc=1)
        # Mock is_satisfiable_fn to return False
        issue = d.check(state, instr, lambda c: False) # type: ignore[arg-type]
        assert issue is not None
        assert issue.kind == IssueKind.UNREACHABLE_CODE

def test_register_advanced_detectors() -> None:
    """Test register_advanced_detectors behavior."""
    r = DetectorRegistry()
    register_advanced_detectors(r)
    assert len(r._detectors) > 0
    assert "null-dereference" in r._detectors
