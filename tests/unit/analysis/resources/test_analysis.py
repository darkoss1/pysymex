import pytest
import dis
from unittest.mock import Mock, patch
from pysymex.analysis.resources.analysis import (
    ResourceKind, ResourceState, Resource, ResourceWarning,
    ResourceLeakDetector, ContextManagerAnalyzer, ObjectNode,
    ReferenceCycleDetector, LockSafetyAnalyzer, GeneratorCleanupAnalyzer,
    ResourceAnalyzer
)

class MockInstr:
    def __init__(self, opname: str, argval: object = None, arg: int | None = None, offset: int = 10, starts_line: int | None = 10) -> None:
        self.opname = opname
        self.argval = argval
        self.arg = arg
        self.offset = offset
        self.starts_line = starts_line

class TestResourceKind:
    """Test suite for pysymex.analysis.resources.analysis.ResourceKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceKind.FILE_HANDLE.name == "FILE_HANDLE"

class TestResourceState:
    """Test suite for pysymex.analysis.resources.analysis.ResourceState."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceState.OPENED.name == "OPENED"

class TestResource:
    """Test suite for pysymex.analysis.resources.analysis.Resource."""
    def test_is_leaked(self) -> None:
        """Test is_leaked behavior."""
        res = Resource(ResourceKind.FILE_HANDLE, "f", 10, 20)
        assert res.is_leaked() is True
        res.in_context_manager = True
        assert res.is_leaked() is False
        res.in_context_manager = False
        res.state = ResourceState.CLOSED
        assert res.is_leaked() is False

class TestResourceWarning:
    """Test suite for pysymex.analysis.resources.analysis.ResourceWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        w = ResourceWarning("LEAK", "f.py", 10, ResourceKind.FILE_HANDLE, "f", "msg")
        assert w.kind == "LEAK"

class TestResourceLeakDetector:
    """Test suite for pysymex.analysis.resources.analysis.ResourceLeakDetector."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions")
    def test_detect(self, mock_instrs) -> None:
        """Test detect behavior."""
        d = ResourceLeakDetector()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE")
        ]
        warnings = d.detect(Mock(co_firstlineno=1)) # type: ignore[arg-type]
        assert len(warnings) > 0
        assert warnings[0].resource_name == "f"

class TestContextManagerAnalyzer:
    """Test suite for pysymex.analysis.resources.analysis.ContextManagerAnalyzer."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions")
    def test_analyze(self, mock_instrs) -> None:
        """Test analyze behavior."""
        c = ContextManagerAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE")
        ]
        warnings = c.analyze(Mock(co_firstlineno=1)) # type: ignore[arg-type]
        assert len(warnings) > 0

class TestObjectNode:
    """Test suite for pysymex.analysis.resources.analysis.ObjectNode."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        n = ObjectNode("n", 10)
        assert n.name == "n"

class TestReferenceCycleDetector:
    """Test suite for pysymex.analysis.resources.analysis.ReferenceCycleDetector."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions")
    def test_detect(self, mock_instrs) -> None:
        """Test detect behavior."""
        d = ReferenceCycleDetector()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "self"),
            MockInstr("STORE_ATTR", "parent"),
            MockInstr("LOAD_FAST", "self"),
            MockInstr("STORE_ATTR", "children")
        ]
        warnings = d.detect(Mock(co_name="__init__", co_firstlineno=1)) # type: ignore[arg-type]
        assert len(warnings) > 0

class TestLockSafetyAnalyzer:
    """Test suite for pysymex.analysis.resources.analysis.LockSafetyAnalyzer."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions")
    def test_analyze(self, mock_instrs) -> None:
        """Test analyze behavior."""
        d = LockSafetyAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "acquire"),
            MockInstr("CALL_METHOD", 0),
            MockInstr("RETURN_VALUE")
        ]
        warnings = d.analyze(Mock(co_firstlineno=1)) # type: ignore[arg-type]
        assert len(warnings) > 0

class TestGeneratorCleanupAnalyzer:
    """Test suite for pysymex.analysis.resources.analysis.GeneratorCleanupAnalyzer."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions")
    def test_analyze(self, mock_instrs) -> None:
        """Test analyze behavior."""
        d = GeneratorCleanupAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("YIELD_VALUE")
        ]
        # set flag to 0x20 for generator
        warnings = d.analyze(Mock(co_firstlineno=1, co_flags=0x20)) # type: ignore[arg-type]
        assert len(warnings) > 0

class TestResourceAnalyzer:
    """Test suite for pysymex.analysis.resources.analysis.ResourceAnalyzer."""
    @patch("pysymex.analysis.resources.analysis._cached_get_instructions", return_value=[])
    def test_analyze_function(self, mock_instr) -> None:
        """Test analyze_function behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_function(Mock(co_firstlineno=1, co_flags=0, co_consts=[])) # type: ignore[arg-type]
        assert isinstance(warnings, list)

    @patch("pysymex.analysis.resources.analysis._cached_get_instructions", return_value=[])
    def test_analyze_module(self, mock_instr) -> None:
        """Test analyze_module behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_module(Mock(co_firstlineno=1, co_flags=0, co_consts=[])) # type: ignore[arg-type]
        assert isinstance(warnings, list)

    @patch("builtins.open", side_effect=OSError)
    def test_analyze_file(self, mock_open) -> None:
        """Test analyze_file behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_file("missing.py")
        assert len(warnings) == 0
