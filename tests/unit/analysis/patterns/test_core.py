import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.patterns.core import (
    PatternKind, PatternMatch, PatternHandler, DictGetHandler,
    DictSetdefaultHandler, DefaultDictAccessHandler, CounterAccessHandler,
    SafeIterationHandler, IsinstanceHandler, NoneCheckHandler, HasattrHandler
)
from pysymex.analysis.type_inference import TypeEnvironment, PyType, TypeKind
import dis

class MockInstr:
    def __init__(self, opname: str, argval: object = None, arg: int | None = None, offset: int = 10, starts_line: int | None = 10) -> None:
        self.opname = opname
        self.argval = argval
        self.arg = arg
        self.offset = offset
        self.starts_line = starts_line
        self.positions = Mock(lineno=starts_line) if starts_line else None

class DummyHandler(PatternHandler):
    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_GET}
    def match(self, instructions, start_idx, env):
        return None

class TestPatternKind:
    """Test suite for pysymex.analysis.patterns.core.PatternKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert PatternKind.DICT_GET.name == "DICT_GET"

class TestPatternMatch:
    """Test suite for pysymex.analysis.patterns.core.PatternMatch."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        pm = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert pm.kind == PatternKind.DICT_GET
        assert pm.confidence == 0.9

class TestPatternHandler:
    """Test suite for pysymex.analysis.patterns.core.PatternHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        d = DummyHandler()
        assert PatternKind.DICT_GET in d.pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        d = DummyHandler()
        assert d.match([], 0, TypeEnvironment()) is None

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        d = DummyHandler()
        pm = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert d.can_raise_error(pm, "Error") is True

class TestDictGetHandler:
    """Test suite for pysymex.analysis.patterns.core.DictGetHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.DICT_GET in DictGetHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = DictGetHandler()
        instrs = [
            MockInstr("LOAD_FAST", "d"),
            MockInstr("LOAD_METHOD", "get"),
            MockInstr("LOAD_CONST", "k"),
            MockInstr("CALL", 1, arg=1)
        ]
        env = TypeEnvironment()
        env.set_type("d", PyType.dict_())
        pm = h.match(instrs, 0, env) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.DICT_GET

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        h = DictGetHandler()
        pm = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert h.can_raise_error(pm, "KeyError") is False
        assert h.can_raise_error(pm, "TypeError") is True

class TestDictSetdefaultHandler:
    """Test suite for pysymex.analysis.patterns.core.DictSetdefaultHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.DICT_SETDEFAULT in DictSetdefaultHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = DictSetdefaultHandler()
        instrs = [
            MockInstr("LOAD_FAST", "d"),
            MockInstr("LOAD_METHOD", "setdefault"),
            MockInstr("LOAD_CONST", "k"),
            MockInstr("LOAD_CONST", 0),
            MockInstr("CALL", 2, arg=2)
        ]
        env = TypeEnvironment()
        pm = h.match(instrs, 0, env) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.DICT_SETDEFAULT

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        h = DictSetdefaultHandler()
        pm = PatternMatch(PatternKind.DICT_SETDEFAULT, 0.9, 10, 20)
        assert h.can_raise_error(pm, "KeyError") is False
        assert h.can_raise_error(pm, "TypeError") is True

class TestDefaultDictAccessHandler:
    """Test suite for pysymex.analysis.patterns.core.DefaultDictAccessHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.DEFAULTDICT_ACCESS in DefaultDictAccessHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = DefaultDictAccessHandler()
        instrs = [
            MockInstr("LOAD_FAST", "d"),
            MockInstr("LOAD_CONST", "k"),
            MockInstr("BINARY_SUBSCR")
        ]
        env = TypeEnvironment()
        env.set_type("d", PyType.defaultdict_())
        pm = h.match(instrs, 0, env) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.DEFAULTDICT_ACCESS

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        h = DefaultDictAccessHandler()
        pm = PatternMatch(PatternKind.DEFAULTDICT_ACCESS, 0.9, 10, 20)
        assert h.can_raise_error(pm, "KeyError") is False
        assert h.can_raise_error(pm, "TypeError") is True

class TestCounterAccessHandler:
    """Test suite for pysymex.analysis.patterns.core.CounterAccessHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.COUNTER_ACCESS in CounterAccessHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = CounterAccessHandler()
        instrs = [
            MockInstr("LOAD_FAST", "c"),
            MockInstr("LOAD_CONST", "k"),
            MockInstr("BINARY_SUBSCR")
        ]
        env = TypeEnvironment()
        # Assume TypeKind.COUNTER is added to PyType
        env.set_type("c", PyType(TypeKind.COUNTER, "Counter", "Counter"))
        pm = h.match(instrs, 0, env) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.COUNTER_ACCESS

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        h = CounterAccessHandler()
        pm = PatternMatch(PatternKind.COUNTER_ACCESS, 0.9, 10, 20)
        assert h.can_raise_error(pm, "KeyError") is False

class TestSafeIterationHandler:
    """Test suite for pysymex.analysis.patterns.core.SafeIterationHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        kinds = SafeIterationHandler().pattern_kinds()
        assert PatternKind.ENUMERATE_ITER in kinds
        assert PatternKind.ZIP_ITER in kinds

    def test_match(self) -> None:
        """Test match behavior."""
        h = SafeIterationHandler()
        instrs = [
            MockInstr("NOP"),
            MockInstr("LOAD_GLOBAL", "enumerate"),
            MockInstr("LOAD_FAST", "lst"),
            MockInstr("CALL", 1),
            MockInstr("GET_ITER")
        ]
        pm = h.match(instrs, 4, TypeEnvironment()) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.ENUMERATE_ITER

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        h = SafeIterationHandler()
        pm = PatternMatch(PatternKind.ENUMERATE_ITER, 0.9, 10, 20, guarantees=["safe_iteration"])
        assert h.can_raise_error(pm, "IndexError") is False
        assert h.can_raise_error(pm, "TypeError") is True

class TestIsinstanceHandler:
    """Test suite for pysymex.analysis.patterns.core.IsinstanceHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.ISINSTANCE_CHECK in IsinstanceHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = IsinstanceHandler()
        instrs = [
            MockInstr("LOAD_GLOBAL", "isinstance"),
            MockInstr("LOAD_FAST", "x"),
            MockInstr("LOAD_GLOBAL", "int"),
            MockInstr("CALL", 2)
        ]
        pm = h.match(instrs, 0, TypeEnvironment()) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.ISINSTANCE_CHECK
        assert pm.variables["type_checked"] == "int"

class TestNoneCheckHandler:
    """Test suite for pysymex.analysis.patterns.core.NoneCheckHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.NONE_CHECK in NoneCheckHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = NoneCheckHandler()
        instrs = [
            MockInstr("LOAD_FAST", "x"),
            MockInstr("LOAD_CONST", None),
            MockInstr("IS_OP", 0) # is
        ]
        pm = h.match(instrs, 0, TypeEnvironment()) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.NONE_CHECK
        assert pm.variables["is_not_none"] is False

class TestHasattrHandler:
    """Test suite for pysymex.analysis.patterns.core.HasattrHandler."""
    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        assert PatternKind.HASATTR_CHECK in HasattrHandler().pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        h = HasattrHandler()
        instrs = [
            MockInstr("LOAD_GLOBAL", "hasattr"),
            MockInstr("LOAD_FAST", "obj"),
            MockInstr("LOAD_CONST", "attr"),
            MockInstr("CALL", 2)
        ]
        pm = h.match(instrs, 0, TypeEnvironment()) # type: ignore[arg-type]
        assert pm is not None
        assert pm.kind == PatternKind.HASATTR_CHECK
