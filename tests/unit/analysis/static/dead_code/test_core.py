from types import CodeType
from unittest.mock import Mock, patch
from pathlib import Path

from pysymex.analysis.static.dead_code.analyzer import DeadCodeAnalyzer
from pysymex.analysis.static.dead_code.conditions import RedundantConditionDetector
from pysymex.analysis.static.dead_code.functions import UnusedFunctionDetector
from pysymex.analysis.static.dead_code.imports import UnusedImportDetector
from pysymex.analysis.static.dead_code.parameters import UnusedParameterDetector
from pysymex.analysis.static.dead_code.stores import DeadStoreDetector
from pysymex.analysis.static.dead_code.unreachable import UnreachableCodeDetector
from pysymex.analysis.static.dead_code.variables import UnusedVariableDetector
from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.analysis.static.dead_code.analyzer import DeadCodeAnalyzer as CanonicalDeadCodeAnalyzer
from pysymex.analysis.static.dead_code.types import DeadCodeKind


def test_dead_code_analyzer_import_paths_are_canonical() -> None:
    import pysymex.analysis as analysis

    assert DeadCodeAnalyzer is CanonicalDeadCodeAnalyzer
    assert analysis.DeadCodeAnalyzer is CanonicalDeadCodeAnalyzer


def make_unused_var_code() -> CodeType:
    module_code = compile(
        "def f():\n    x = 1\n    y = 2\n    print(x)\n",
        "<dead-code-test>",
        "exec",
    )
    code_objects = [const for const in module_code.co_consts if isinstance(const, CodeType)]
    assert len(code_objects) == 1
    return code_objects[0]


def make_dead_store_code() -> CodeType:
    def f() -> None:
        x = 1
        x = 2
        print(x)

    return f.__code__


def make_unused_param_code() -> CodeType:
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
    """Test suite for canonical dead-code UnreachableCodeDetector."""

    @patch("pysymex.analysis.static.dead_code.unreachable.cached_get_instructions")
    def test_detect(self, mock_get_instr: Mock) -> None:
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
    """Test suite for canonical dead-code UnusedVariableDetector."""

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

            _ = g

        uses = UnusedVariableDetector.collect_nested_uses(f.__code__)
        assert "x" in uses


class TestDeadStoreDetector:
    """Test suite for canonical dead-code DeadStoreDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = DeadStoreDetector()
        code = make_dead_store_code()
        issues = detector.detect(code)
        assert len(issues) == 1
        assert issues[0].name == "x"
        assert issues[0].kind == DeadCodeKind.DEAD_STORE

    @patch(
        "pysymex.analysis.static.dataflow.liveness.LiveVariables.__init__",
        side_effect=AssertionError("dead-store detection should not instantiate liveness"),
    )
    def test_detect_does_not_depend_on_liveness_analysis(self, mock_live_init: Mock) -> None:
        detector = DeadStoreDetector()
        code = make_dead_store_code()
        issues = detector.detect(code)

        assert len(issues) == 1
        assert issues[0].name == "x"
        assert issues[0].kind == DeadCodeKind.DEAD_STORE
        mock_live_init.assert_not_called()


class TestUnusedFunctionDetector:
    """Test suite for canonical dead-code UnusedFunctionDetector."""

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
    """Test suite for canonical dead-code UnusedParameterDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = UnusedParameterDetector()
        code = make_unused_param_code()
        issues = detector.detect(code)
        assert len(issues) == 1
        assert issues[0].name == "b"
        assert issues[0].kind == DeadCodeKind.UNUSED_PARAMETER


class TestUnusedImportDetector:
    """Test suite for canonical dead-code UnusedImportDetector."""

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
    """Test suite for canonical dead-code RedundantConditionDetector."""

    @patch("pysymex.analysis.static.dead_code.conditions.cached_get_instructions")
    def test_detect(self, mock_get_instr: Mock) -> None:
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


class TestDeadCodeAnalyzer:
    def test_analyze_file_reports_syntax_error_as_analysis_error(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.py"
        target.write_text("def bad(:\n    pass\n", encoding="utf-8")
        analyzer = DeadCodeAnalyzer()

        issues = analyzer.analyze_file(str(target))

        assert len(issues) == 1
        assert issues[0].kind == DeadCodeKind.ANALYSIS_ERROR
        assert issues[0].confidence == 0.0
        assert "Syntax error prevents analysis" in issues[0].message

    def test_analyze_file_reports_non_syntax_failure_as_analysis_error(
        self,
        tmp_path: Path,
    ) -> None:
        missing = tmp_path / "missing.py"
        analyzer = DeadCodeAnalyzer()

        issues = analyzer.analyze_file(str(missing))

        assert len(issues) == 1
        assert issues[0].kind == DeadCodeKind.ANALYSIS_ERROR
        assert issues[0].confidence == 0.0
        assert "Dead code analysis failed: FileNotFoundError" in issues[0].message
