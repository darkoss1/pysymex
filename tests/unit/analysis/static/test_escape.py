from collections.abc import Callable
from unittest.mock import MagicMock, Mock, patch

from pysymex.analysis.static.escape import EscapeAnalyzer, EscapeInfo, EscapeState


class TestEscapeState:
    """Test suite for pysymex.analysis.static.escape.EscapeState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert EscapeState.NO_ESCAPE.name == "NO_ESCAPE"
        assert EscapeState.GLOBAL_ESCAPE.name == "GLOBAL_ESCAPE"


class TestEscapeInfo:
    """Test suite for pysymex.analysis.static.escape.EscapeInfo."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = EscapeInfo(EscapeState.NO_ESCAPE)
        assert info.state == EscapeState.NO_ESCAPE


class TestEscapeAnalyzer:
    """Test suite for pysymex.analysis.static.escape.EscapeAnalyzer."""

    @patch("pysymex.analysis.static.escape.cached_get_instructions")
    def test_analyze_function(self, mock_instrs: MagicMock) -> None:
        """Test analyze_function behavior."""
        mock_instrs.return_value = []
        analyzer = EscapeAnalyzer()
        res = analyzer.analyze_function(Mock(co_varnames=("a", "b"), co_argcount=2))
        assert isinstance(res, dict)

    def test_keyword_argument_allocation_escapes_to_call(self) -> None:
        """CALL_KW marks real keyword argument allocations, not keyword metadata."""

        def target(sink: Callable[..., object]) -> None:
            sink(items=[1])

        result = EscapeAnalyzer.analyze_function(target.__code__)

        assert any(info.state == EscapeState.ARG_ESCAPE for info in result.values())

    def test_splat_argument_allocation_escapes_to_call(self) -> None:
        """CALL_FUNCTION_EX marks the *args container as escaping to the callee."""

        def target(sink: Callable[..., object]) -> None:
            sink(*[1])

        result = EscapeAnalyzer.analyze_function(target.__code__)

        assert any(info.state == EscapeState.ARG_ESCAPE for info in result.values())
