from unittest.mock import Mock, patch
from pathlib import Path

from pysymex.analysis.domains.resources.context_managers import ContextManagerAnalyzer
from pysymex.analysis.domains.resources.generator_cleanup import GeneratorCleanupAnalyzer
from pysymex.analysis.domains.resources.leak_detection import ResourceLeakAnalyzer
from pysymex.analysis.domains.resources.lock_safety import LockSafetyAnalyzer
from pysymex.analysis.domains.resources.reference_cycles import ReferenceCycleDetector
from pysymex.analysis.domains.resources.resource_analyzer import ResourceAnalyzer
from pysymex.analysis.domains.resources.usage import (
    ObjectNode,
    Resource,
    ResourceKind,
    ResourceState,
    ResourceWarning,
)


class MockInstr:
    def __init__(
        self,
        opname: str,
        argval: object = None,
        arg: int | None = None,
        offset: int = 10,
        starts_line: int | None = 10,
    ) -> None:
        self.opname = opname
        self.argval = argval
        self.arg = arg
        self.offset = offset
        self.starts_line = starts_line


class TestResourceKind:
    """Test suite for pysymex.analysis.domains.resources.types.ResourceKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceKind.FILE_HANDLE.name == "FILE_HANDLE"


class TestResourceState:
    """Test suite for pysymex.analysis.domains.resources.types.ResourceState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceState.OPENED.name == "OPENED"


class TestResource:
    """Test suite for pysymex.analysis.domains.resources.usage.Resource."""

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
    """Test suite for pysymex.analysis.domains.resources.usage.ResourceWarning."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        w = ResourceWarning("LEAK", "f.py", 10, ResourceKind.FILE_HANDLE, "f", "msg")
        assert w.kind == "LEAK"


class TestResourceLeakAnalyzer:
    """Test suite for pysymex.analysis.domains.resources.leak_detection.ResourceLeakAnalyzer."""

    @patch("pysymex.analysis.domains.resources.leak_detection.cached_get_instructions")
    def test_detect(self, mock_instrs: Mock) -> None:
        """Test detect behavior."""
        d = ResourceLeakAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.detect(Mock(co_firstlineno=1))
        assert len(warnings) > 0
        assert warnings[0].resource_name == "f"

    @patch("pysymex.analysis.domains.resources.leak_detection.cached_get_instructions")
    def test_detect_ignores_zero_argument_builtin_open(self, mock_instrs: Mock) -> None:
        """Do not report leaks for open() calls CPython rejects before opening."""
        d = ResourceLeakAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 0),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.detect(Mock(co_firstlineno=1))
        assert warnings == []

    @patch("pysymex.analysis.domains.resources.leak_detection.cached_get_instructions")
    def test_detect_tracks_keyword_open_call(self, mock_instrs: Mock) -> None:
        """Keyword open(file=...) calls are valid resource openers."""
        d = ResourceLeakAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("LOAD_CONST", "target.txt"),
            MockInstr("LOAD_CONST", ("file",)),
            MockInstr("CALL_KW", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.detect(Mock(co_firstlineno=1))
        assert len(warnings) == 1
        assert warnings[0].resource_name == "f"


class TestContextManagerAnalyzer:
    """Test suite for pysymex.analysis.domains.resources.context_managers.ContextManagerAnalyzer."""

    @patch("pysymex.analysis.domains.resources.context_managers.cached_get_instructions")
    def test_analyze(self, mock_instrs: Mock) -> None:
        """Test analyze behavior."""
        c = ContextManagerAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = c.analyze(Mock(co_firstlineno=1))
        assert len(warnings) > 0

    @patch("pysymex.analysis.domains.resources.context_managers.cached_get_instructions")
    def test_analyze_ignores_bare_open_reference(self, mock_instrs: Mock) -> None:
        """Do not warn for loading open without calling it."""
        c = ContextManagerAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = c.analyze(Mock(co_firstlineno=1))
        assert warnings == []

    @patch("pysymex.analysis.domains.resources.context_managers.cached_get_instructions")
    def test_analyze_ignores_zero_argument_builtin_open(self, mock_instrs: Mock) -> None:
        """Do not warn for open() calls CPython rejects before opening."""
        c = ContextManagerAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 0),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = c.analyze(Mock(co_firstlineno=1))
        assert warnings == []

    @patch("pysymex.analysis.domains.resources.context_managers.cached_get_instructions")
    def test_analyze_warns_for_keyword_open_without_with(self, mock_instrs: Mock) -> None:
        """Keyword open(file=...) calls still need context managers."""
        c = ContextManagerAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("LOAD_CONST", "target.txt"),
            MockInstr("LOAD_CONST", ("file",)),
            MockInstr("CALL_KW", 1),
            MockInstr("STORE_FAST", "f"),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = c.analyze(Mock(co_firstlineno=1))
        assert len(warnings) == 1
        assert warnings[0].kind == "MISSING_CONTEXT_MANAGER"


class TestObjectNode:
    """Test suite for pysymex.analysis.domains.resources.usage.ObjectNode."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        n = ObjectNode("n", 10)
        assert n.name == "n"


class TestReferenceCycleDetector:
    """Test suite for pysymex.analysis.domains.resources.reference_cycles.ReferenceCycleDetector."""

    @patch("pysymex.analysis.domains.resources.reference_cycles.cached_get_instructions")
    def test_detect(self, mock_instrs: Mock) -> None:
        """Test detect behavior."""
        d = ReferenceCycleDetector()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "self"),
            MockInstr("STORE_ATTR", "parent"),
            MockInstr("LOAD_FAST", "self"),
            MockInstr("STORE_ATTR", "children"),
        ]
        warnings = d.detect(Mock(co_name="__init__", co_firstlineno=1))
        assert len(warnings) > 0


class TestLockSafetyAnalyzer:
    """Test suite for pysymex.analysis.domains.resources.lock_safety.LockSafetyAnalyzer."""

    @patch("pysymex.analysis.domains.resources.lock_safety.cached_get_instructions")
    def test_analyze(self, mock_instrs: Mock) -> None:
        """Test analyze behavior."""
        d = LockSafetyAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "acquire"),
            MockInstr("CALL_METHOD", 0),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1))
        assert len(warnings) > 0

    @patch("pysymex.analysis.domains.resources.lock_safety.cached_get_instructions")
    def test_analyze_does_not_treat_extra_argument_release_as_success(
        self, mock_instrs: Mock
    ) -> None:
        """Do not clear acquired lock state for release calls CPython rejects."""
        d = LockSafetyAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "acquire"),
            MockInstr("CALL_METHOD", 0),
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "release"),
            MockInstr("LOAD_CONST", 1),
            MockInstr("CALL_METHOD", 1),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1))
        assert any(warning.kind == "LOCK_NOT_RELEASED" for warning in warnings)

    @patch("pysymex.analysis.domains.resources.lock_safety.cached_get_instructions")
    def test_analyze_does_not_treat_keyword_release_as_success(self, mock_instrs: Mock) -> None:
        """CALL_KW release calls with arguments do not clear acquired lock state."""
        d = LockSafetyAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "acquire"),
            MockInstr("CALL_METHOD", 0),
            MockInstr("LOAD_FAST", "lock"),
            MockInstr("LOAD_METHOD", "release"),
            MockInstr("LOAD_CONST", False),
            MockInstr("LOAD_CONST", ("blocking",)),
            MockInstr("CALL_KW", 1),
            MockInstr("RETURN_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1))
        assert any(warning.kind == "LOCK_NOT_RELEASED" for warning in warnings)


class TestGeneratorCleanupAnalyzer:
    """Test suite for pysymex.analysis.domains.resources.generator_cleanup.GeneratorCleanupAnalyzer."""

    @patch("pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions")
    def test_analyze(self, mock_instrs: Mock) -> None:
        """Test analyze behavior."""
        d = GeneratorCleanupAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 1),
            MockInstr("YIELD_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1, co_flags=0x20))
        assert len(warnings) > 0

    @patch("pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions")
    def test_analyze_ignores_bare_open_reference(self, mock_instrs: Mock) -> None:
        """Do not warn for loading open without calling it."""
        d = GeneratorCleanupAnalyzer()
        mock_instrs.return_value = [MockInstr("LOAD_GLOBAL", "open"), MockInstr("YIELD_VALUE")]
        warnings = d.analyze(Mock(co_firstlineno=1, co_flags=0x20))
        assert warnings == []

    @patch("pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions")
    def test_analyze_ignores_zero_argument_builtin_open(self, mock_instrs: Mock) -> None:
        """Do not warn for open() calls CPython rejects before opening."""
        d = GeneratorCleanupAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("CALL_FUNCTION", 0),
            MockInstr("YIELD_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1, co_flags=0x20))
        assert warnings == []

    @patch("pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions")
    def test_analyze_warns_for_keyword_open_in_generator(self, mock_instrs: Mock) -> None:
        """Generator cleanup analysis recognizes keyword open(file=...) calls."""
        d = GeneratorCleanupAnalyzer()
        mock_instrs.return_value = [
            MockInstr("LOAD_GLOBAL", "open"),
            MockInstr("LOAD_CONST", "target.txt"),
            MockInstr("LOAD_CONST", ("file",)),
            MockInstr("CALL_KW", 1),
            MockInstr("YIELD_VALUE"),
        ]
        warnings = d.analyze(Mock(co_firstlineno=1, co_flags=0x20))
        assert len(warnings) == 1
        assert warnings[0].kind == "GENERATOR_RESOURCE_LEAK"


class TestResourceAnalyzer:
    """Test suite for pysymex.analysis.domains.resources.resource_analyzer.ResourceAnalyzer."""

    @patch(
        "pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.lock_safety.cached_get_instructions", return_value=[]
    )
    @patch(
        "pysymex.analysis.domains.resources.reference_cycles.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.context_managers.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.leak_detection.cached_get_instructions", return_value=[]
    )
    def test_analyze_function(self, *_mocks: Mock) -> None:
        """Test analyze_function behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_function(Mock(co_firstlineno=1, co_flags=0, co_consts=[]))
        assert isinstance(warnings, list)

    @patch(
        "pysymex.analysis.domains.resources.generator_cleanup.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.lock_safety.cached_get_instructions", return_value=[]
    )
    @patch(
        "pysymex.analysis.domains.resources.reference_cycles.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.context_managers.cached_get_instructions",
        return_value=[],
    )
    @patch(
        "pysymex.analysis.domains.resources.leak_detection.cached_get_instructions", return_value=[]
    )
    def test_analyze_module(self, *_mocks: Mock) -> None:
        """Test analyze_module behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_module(Mock(co_firstlineno=1, co_flags=0, co_consts=[]))
        assert isinstance(warnings, list)

    @patch("builtins.open", side_effect=OSError)
    def test_analyze_file(self, _mock_open: Mock) -> None:
        """Test analyze_file behavior."""
        analyzer = ResourceAnalyzer()
        warnings = analyzer.analyze_file("missing.py")
        assert len(warnings) == 1
        assert warnings[0].kind == "ANALYSIS_ERROR"
        assert warnings[0].severity == "error"
        assert "OSError" in warnings[0].message

    def test_analyze_file_reports_syntax_error(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.py"
        target.write_text("def bad(:\n    pass\n", encoding="utf-8")
        analyzer = ResourceAnalyzer()

        warnings = analyzer.analyze_file(str(target))

        assert len(warnings) == 1
        assert warnings[0].kind == "ANALYSIS_ERROR"
        assert warnings[0].severity == "error"
        assert "SyntaxError" in warnings[0].message
