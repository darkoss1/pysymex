import dis
from types import FunctionType

from pysymex.analysis.static.patterns.iteration import SafeIterationHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.patterns.type_guards import (
    HasattrHandler,
    IsinstanceHandler,
    NoneCheckHandler,
)
from pysymex.analysis.static.types import TypeEnvironment

from .pattern_fixtures import mock_instr


def _index_of(instructions: list[dis.Instruction], opname: str, argval: object = None) -> int:
    for index, instruction in enumerate(instructions):
        if instruction.opname == opname and (argval is None or instruction.argval == argval):
            return index
    raise AssertionError(f"{opname} {argval!r} not found")


def _compile_function(source: str, name: str = "target") -> FunctionType:
    namespace: dict[str, object] = {}
    exec(source, namespace)
    target = namespace[name]
    assert isinstance(target, FunctionType)
    return target


class TestSafeIterationHandler:
    """Test suite for pysymex.analysis.static.patterns.iteration.SafeIterationHandler."""

    def test_pattern_kinds(self) -> None:
        kinds = SafeIterationHandler().pattern_kinds()
        assert PatternKind.ENUMERATE_ITER in kinds
        assert PatternKind.ZIP_ITER in kinds

    def test_match(self) -> None:
        handler = SafeIterationHandler()
        instrs = [
            mock_instr("NOP"),
            mock_instr("LOAD_GLOBAL", "enumerate"),
            mock_instr("LOAD_FAST", "lst"),
            mock_instr("CALL", 1),
            mock_instr("GET_ITER"),
        ]
        match = handler.match(instrs, 4, TypeEnvironment())
        assert match is not None
        assert match.kind == PatternKind.ENUMERATE_ITER

    def test_match_enumerate_keyword_call_real_bytecode(self) -> None:
        target = _compile_function(
            "def target(xs):\n    for index, value in enumerate(xs, start=1):\n        pass\n"
        )
        instrs = list(dis.get_instructions(target))
        match = SafeIterationHandler().match(
            instrs, _index_of(instrs, "GET_ITER"), TypeEnvironment()
        )
        assert match is not None
        assert match.kind == PatternKind.ENUMERATE_ITER

    def test_match_zip_splat_call_real_bytecode(self) -> None:
        target = _compile_function(
            "def target(args):\n    for value in zip(*args):\n        pass\n"
        )
        instrs = list(dis.get_instructions(target))
        match = SafeIterationHandler().match(
            instrs, _index_of(instrs, "GET_ITER"), TypeEnvironment()
        )
        assert match is not None
        assert match.kind == PatternKind.ZIP_ITER

    def test_can_raise_error(self) -> None:
        handler = SafeIterationHandler()
        match = PatternMatch(PatternKind.ENUMERATE_ITER, 0.9, 10, 20, guarantees=["safe_iteration"])
        assert handler.can_raise_error(match, "IndexError") is False
        assert handler.can_raise_error(match, "TypeError") is True


class TestIsinstanceHandler:
    """Test suite for pysymex.analysis.static.patterns.type_guards.IsinstanceHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.ISINSTANCE_CHECK in IsinstanceHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = IsinstanceHandler()
        instrs = [
            mock_instr("LOAD_GLOBAL", "isinstance"),
            mock_instr("LOAD_FAST", "x"),
            mock_instr("LOAD_GLOBAL", "int"),
            mock_instr("CALL", 2),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is not None
        assert match.kind == PatternKind.ISINSTANCE_CHECK
        assert match.variables["type_checked"] == "int"

    def test_rejects_wrong_isinstance_arity(self) -> None:
        handler = IsinstanceHandler()
        instrs = [
            mock_instr("LOAD_GLOBAL", "isinstance"),
            mock_instr("LOAD_FAST", "x"),
            mock_instr("LOAD_GLOBAL", "int"),
            mock_instr("LOAD_GLOBAL", "str"),
            mock_instr("CALL", 3),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is None


class TestNoneCheckHandler:
    """Test suite for pysymex.analysis.static.patterns.type_guards.NoneCheckHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.NONE_CHECK in NoneCheckHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = NoneCheckHandler()
        instrs = [
            mock_instr("LOAD_FAST", "x"),
            mock_instr("LOAD_CONST", None),
            mock_instr("IS_OP", 0),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is not None
        assert match.kind == PatternKind.NONE_CHECK
        assert match.variables["is_not_none"] is False


class TestHasattrHandler:
    """Test suite for pysymex.analysis.static.patterns.type_guards.HasattrHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.HASATTR_CHECK in HasattrHandler().pattern_kinds()

    def test_match(self) -> None:
        handler = HasattrHandler()
        instrs = [
            mock_instr("LOAD_GLOBAL", "hasattr"),
            mock_instr("LOAD_FAST", "obj"),
            mock_instr("LOAD_CONST", "attr"),
            mock_instr("CALL", 2),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is not None
        assert match.kind == PatternKind.HASATTR_CHECK

    def test_rejects_keyword_call_to_positional_only_hasattr(self) -> None:
        handler = HasattrHandler()
        instrs = [
            mock_instr("LOAD_GLOBAL", "hasattr"),
            mock_instr("LOAD_FAST", "obj"),
            mock_instr("LOAD_CONST", "attr"),
            mock_instr("LOAD_CONST", ("obj", "name")),
            mock_instr("CALL_KW", 2, arg=2),
        ]
        match = handler.match(instrs, 0, TypeEnvironment())
        assert match is None
