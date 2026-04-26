import pytest
import dis
from unittest.mock import patch, Mock
from pysymex.analysis.dead_code.core import (
    UnreachableCodeDetector,
    UnusedVariableDetector,
    DeadStoreDetector,
    UnusedFunctionDetector,
    UnusedParameterDetector,
    UnusedImportDetector,
    RedundantConditionDetector,
)
from pysymex.analysis.cross_function.core import CallGraph
from pysymex.analysis.dead_code.types import DeadCodeKind


def make_unused_var_code() -> object:
    def f() -> None:
        x = 1
        y = 2
        print(x)

    return f.__code__


def make_dead_store_code() -> object:
    def f() -> None:
        x = 1
        x = 2
        print(x)

    return f.__code__


def make_unused_param_code() -> object:
    def f(a: int, b: int) -> int:
        return a

    return f.__code__


class MockInstr:
    def __init__(
        self,
        opname: str,
        offset: int,
        argval: object = None,
        is_jump_target: bool = False,
        starts_line: int | None = None,
    ) -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.is_jump_target = is_jump_target
        self.starts_line = starts_line
        self.positions = Mock(lineno=starts_line) if starts_line else None


class TestUnreachableCodeDetector:
    """Test suite for pysymex.analysis.dead_code.core.UnreachableCodeDetector."""

    @patch("pysymex.analysis.dead_code.core._cached_get_instructions")
    def test_detect(self, mock_get_instr) -> None:
        """Test detect behavior."""
        mock_get_instr.return_value = [
            MockInstr("LOAD_CONST", 0, 1, starts_line=10),
            MockInstr("RETURN_VALUE", 2),
            MockInstr("LOAD_GLOBAL", 4, "print", starts_line=11),
            MockInstr("LOAD_CONST", 6, "unreachable"),
            MockInstr("CALL", 8),
            MockInstr("POP_TOP", 10),
        ]
        detector = UnreachableCodeDetector()
        mock_code = Mock()
        mock_code.co_flags = 0
        mock_code.co_firstlineno = 10
        mock_code.co_name = "f"
        mock_code.co_qualname = "f"
        issues = detector.detect(mock_code)
        assert len(issues) >= 1
        assert issues[0].kind == DeadCodeKind.UNREACHABLE_CODE
        assert issues[0].line == 11


class TestUnusedVariableDetector:
    """Test suite for pysymex.analysis.dead_code.core.UnusedVariableDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = UnusedVariableDetector()
        code = make_unused_var_code()
        issues = detector.detect(code)
        assert len(issues) == 1
        assert issues[0].name == "y"
        assert issues[0].kind == DeadCodeKind.UNUSED_VARIABLE

    def test_collect_nested_uses(self) -> None:
        """Test collect_nested_uses behavior."""

        def f() -> None:
            x = 1

            def g() -> None:
                print(x)

        uses = UnusedVariableDetector.collect_nested_uses(f.__code__)
        assert "x" in uses


class TestDeadStoreDetector:
    """Test suite for pysymex.analysis.dead_code.core.DeadStoreDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = DeadStoreDetector()
        code = make_dead_store_code()
        issues = detector.detect(code)
        assert len(issues) == 1
        assert issues[0].name == "x"
        assert issues[0].kind == DeadCodeKind.DEAD_STORE


class TestUnusedFunctionDetector:
    """Test suite for pysymex.analysis.dead_code.core.UnusedFunctionDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = UnusedFunctionDetector()
        cg = CallGraph()
        cg.add_function("f1")
        cg.add_call("f2", "f3", 1, 1)
        issues = detector.detect(cg)
        names = [i.name for i in issues]
        assert "f1" in names
        assert "f2" in names
        assert "f3" not in names


class TestUnusedParameterDetector:
    """Test suite for pysymex.analysis.dead_code.core.UnusedParameterDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = UnusedParameterDetector()
        code = make_unused_param_code()
        issues = detector.detect(code)
        assert len(issues) == 1
        assert issues[0].name == "b"
        assert issues[0].kind == DeadCodeKind.UNUSED_PARAMETER


class TestUnusedImportDetector:
    """Test suite for pysymex.analysis.dead_code.core.UnusedImportDetector."""

    def test_detect_from_source(self) -> None:
        """Test detect_from_source behavior."""
        detector = UnusedImportDetector()
        source = """
import os
import sys
import json as j
print(os.path)
        """
        issues = detector.detect_from_source(source)
        names = [i.name for i in issues]
        assert "sys" in names
        assert "j" in names
        assert "os" not in names


class TestRedundantConditionDetector:
    """Test suite for pysymex.analysis.dead_code.core.RedundantConditionDetector."""

    @patch("pysymex.analysis.dead_code.core._cached_get_instructions")
    def test_detect(self, mock_get_instr) -> None:
        """Test detect behavior."""
        mock_get_instr.return_value = [
            MockInstr("LOAD_CONST", 0, True, starts_line=10),
            MockInstr("POP_JUMP_IF_FALSE", 2, 10),
        ]
        detector = RedundantConditionDetector()
        mock_code = Mock(co_firstlineno=10)
        issues = detector.detect(mock_code)
        assert len(issues) >= 1
        assert issues[0].kind == DeadCodeKind.REDUNDANT_CONDITION
