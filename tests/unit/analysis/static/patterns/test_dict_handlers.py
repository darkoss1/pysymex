import dis
from types import FunctionType

from pysymex.analysis.static.patterns.dict.access import (
    CounterAccessHandler,
    DefaultDictAccessHandler,
)
from pysymex.analysis.static.patterns.dict.methods import DictGetHandler, DictSetdefaultHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment, TypeKind

from .pattern_fixtures import mock_instr


def _index_of(instructions: list[dis.Instruction], opname: str, argval: object) -> int:
    for index, instruction in enumerate(instructions):
        if instruction.opname == opname and instruction.argval == argval:
            return index
    raise AssertionError(f"{opname} {argval!r} not found")


class TestDictGetHandler:
    """Test suite for pysymex.analysis.static.patterns.dict.methods.DictGetHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.DICT_GET in DictGetHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = DictGetHandler()
        instrs = [
            mock_instr("LOAD_FAST", "d"),
            mock_instr("LOAD_METHOD", "get"),
            mock_instr("LOAD_CONST", "k"),
            mock_instr("CALL", 1, arg=1),
        ]
        env = TypeEnvironment()
        env.set_type("d", PyType.dict_())
        match = handler.match(instrs, 0, env)
        assert match is not None
        assert match.kind == PatternKind.DICT_GET

    def test_rejects_keyword_call_to_positional_only_dict_get(self) -> None:
        namespace: dict[str, object] = {}
        exec('def target(d):\n    return d.get("missing", default=0)\n', namespace)
        handler = DictGetHandler()
        target = namespace["target"]
        assert isinstance(target, FunctionType)
        instrs = list(dis.get_instructions(target))
        env = TypeEnvironment()
        env.set_type("d", PyType.dict_())
        match = handler.match(instrs, _index_of(instrs, "LOAD_FAST", "d"), env)
        assert match is None

    def test_can_raise_error(self) -> None:
        handler = DictGetHandler()
        match = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert handler.can_raise_error(match, "KeyError") is False
        assert handler.can_raise_error(match, "TypeError") is True


class TestDictSetdefaultHandler:
    """Test suite for pysymex.analysis.static.patterns.dict.methods.DictSetdefaultHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.DICT_SETDEFAULT in DictSetdefaultHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = DictSetdefaultHandler()
        instrs = [
            mock_instr("LOAD_FAST", "d"),
            mock_instr("LOAD_METHOD", "setdefault"),
            mock_instr("LOAD_CONST", "k"),
            mock_instr("LOAD_CONST", 0),
            mock_instr("CALL", 2, arg=2),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is not None
        assert match.kind == PatternKind.DICT_SETDEFAULT

    def test_rejects_bare_setdefault_attribute_without_call(self) -> None:
        handler = DictSetdefaultHandler()
        instrs = [
            mock_instr("LOAD_FAST", "d"),
            mock_instr("LOAD_METHOD", "setdefault"),
            mock_instr("NOP"),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is None

    def test_rejects_wrong_setdefault_arity(self) -> None:
        handler = DictSetdefaultHandler()
        instrs = [
            mock_instr("LOAD_FAST", "d"),
            mock_instr("LOAD_METHOD", "setdefault"),
            mock_instr("CALL", 0, arg=0),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is None

    def test_can_raise_error(self) -> None:
        handler = DictSetdefaultHandler()
        match = PatternMatch(PatternKind.DICT_SETDEFAULT, 0.9, 10, 20)
        assert handler.can_raise_error(match, "KeyError") is False
        assert handler.can_raise_error(match, "TypeError") is True


class TestDefaultDictAccessHandler:
    """Test suite for pysymex.analysis.static.patterns.dict.access.DefaultDictAccessHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.DEFAULTDICT_ACCESS in DefaultDictAccessHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = DefaultDictAccessHandler()
        instrs = [
            mock_instr("LOAD_FAST", "d"),
            mock_instr("LOAD_CONST", "k"),
            mock_instr("BINARY_SUBSCR"),
        ]
        env = TypeEnvironment()
        env.set_type("d", PyType.defaultdict_())
        match = handler.match(instrs, 0, env)
        assert match is not None
        assert match.kind == PatternKind.DEFAULTDICT_ACCESS

    def test_can_raise_error(self) -> None:
        handler = DefaultDictAccessHandler()
        match = PatternMatch(PatternKind.DEFAULTDICT_ACCESS, 0.9, 10, 20)
        assert handler.can_raise_error(match, "KeyError") is False
        assert handler.can_raise_error(match, "TypeError") is True


class TestCounterAccessHandler:
    """Test suite for pysymex.analysis.static.patterns.dict.access.CounterAccessHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.COUNTER_ACCESS in CounterAccessHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = CounterAccessHandler()
        instrs = [
            mock_instr("LOAD_FAST", "c"),
            mock_instr("LOAD_CONST", "k"),
            mock_instr("BINARY_SUBSCR"),
        ]
        env = TypeEnvironment()
        env.set_type("c", PyType(TypeKind.COUNTER, "Counter", class_name="Counter"))
        match = handler.match(instrs, 0, env)
        assert match is not None
        assert match.kind == PatternKind.COUNTER_ACCESS

    def test_can_raise_error(self) -> None:
        handler = CounterAccessHandler()
        match = PatternMatch(PatternKind.COUNTER_ACCESS, 0.9, 10, 20)
        assert handler.can_raise_error(match, "KeyError") is False
